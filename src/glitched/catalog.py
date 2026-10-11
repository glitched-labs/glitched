"""
Shared vocabulary for describing a robot / IoT device.

Customers describe their device in plain terms (ROS, Unitree, Bluetooth, OTA
updates, ...). Threat intel is indexed by CVE platform tags (research_cves) and
EMB3D property ids (PID-###). This module is the single translation layer
between the two, used by:

  - pipelines/transform tags CVEs with the same keywords (seeds/platform_keywords.csv)
  - device_profile.py   to turn questionnaire answers, SBOM components and
                        scan results into tags + EMB3D properties
  - queries.py          to decide which tags identify a platform
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Tags
# --------------------------------------------------------------------------

# Keyword (matched as a whole word, case-insensitive) -> normalised tag.
# Kept in a dbt seed so CVE tagging (stg_research__cves) and the app share one list.
KEYWORDS_CSV = Path(__file__).resolve().parent / "pipelines" / "transform" / "seeds" / "platform_keywords.csv"
with KEYWORDS_CSV.open(newline="") as _f:
    PLATFORM_KEYWORDS: dict[str, str] = {row["keyword"]: row["tag"] for row in csv.DictReader(_f)}

# Tags that name a vendor/platform. A CVE carrying one of these only applies to
# devices built on that platform - a generic "wifi" match is not enough.
PLATFORMS = {
    "ros": "ROS / ROS 2",
    "universal-robots": "Universal Robots (PolyScope)",
    "unitree": "Unitree (Go2, G1, H1, B2)",
    "lerobot": "Hugging Face LeRobot",
}

# ROS distros -> ROS generation. NVD versions core ROS CVEs by generation ("2")
# or by distro ("noetic_ninjemys"), so knowing the distro decides which apply.
ROS_DISTROS: dict[str, int] = {
    "indigo": 1, "jade": 1, "kinetic": 1, "lunar": 1, "melodic": 1, "noetic": 1,
    "ardent": 2, "bouncy": 2, "crystal": 2, "dashing": 2, "eloquent": 2, "foxy": 2,
    "galactic": 2, "humble": 2, "iron": 2, "jazzy": 2, "kilted": 2, "rolling": 2,
}

# NVD products that are ROS itself (every ROS install has them) -> the generation
# they belong to (None: decided by the CVE's version field).
ROS_CORE: dict[tuple[str, str], int | None] = {
    ("openrobotics", "robot_operating_system"): None,
    ("ros", "ros-comm"): 1,
}
# Vendors whose other products are ROS packages: only apply if the SBOM lists them.
ROS_VENDORS = {"openrobotics", "ros", "opennav", "moveit", "robotwebtools", "ntpd_driver_project"}
# NVD product name -> package names an SBOM may use for it.
PRODUCT_ALIASES: dict[str, tuple[str, ...]] = {
    "nav2": ("navigation2", "nav2"),
    "ros_comm": ("ros_comm", "roscpp", "rospy", "rosmaster", "rosgraph", "roslaunch"),
    "moveit": ("moveit", "moveit_core", "moveit_ros_planning"),
}

# Connectivity tags a customer can declare.
INTERFACES = {
    "wifi": "Wi-Fi",
    "bluetooth": "Bluetooth / BLE",
    "mqtt": "MQTT",
    "rosbridge": "rosbridge (ROS over WebSocket)",
    "telnet": "Telnet",
    "rtsp": "RTSP camera stream",
    "coap": "CoAP",
    "cloud-teleop": "Cloud teleoperation / remote control",
}

_KEYWORD_PATTERNS = [
    (re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE), tag)
    for kw, tag in PLATFORM_KEYWORDS.items()
]


def infer_tags(text: str) -> list[str]:
    """Whole-word keyword match, so 'ble' doesn't fire on 'vulnerable'."""
    return sorted({tag for pattern, tag in _KEYWORD_PATTERNS if pattern.search(text)})


# --------------------------------------------------------------------------
# Questionnaire
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Question:
    """A yes/no question. Answers add tags and/or EMB3D property ids."""

    key: str
    prompt: str
    yes_tags: tuple[str, ...] = ()
    yes_properties: tuple[str, ...] = ()
    no_properties: tuple[str, ...] = ()
    # Only asked when this question is answered yes.
    followups: tuple[Question, ...] = field(default_factory=tuple)


QUESTIONS: tuple[Question, ...] = (
    Question("os", "Does it run a full operating system (e.g. Linux on a Jetson or Raspberry Pi)?",
             yes_properties=("PID-11", "PID-23", "PID-231")),
    Question("network", "Does it accept connections over a network (Wi-Fi, Ethernet, cellular)?",
             yes_properties=("PID-41",),
             followups=(
                 Question("wifi", "Wi-Fi?", yes_tags=("wifi",)),
                 Question("web", "Does it serve a web UI or HTTP API?",
                          yes_properties=("PID-311", "PID-33")),
                 Question("unauthenticated", "Can anything on it be reached without logging in "
                          "(e.g. ROS master, rosbridge, a dashboard port)?",
                          yes_properties=("PID-331",)),
                 Question("passwords", "Do users or other systems log in with passwords?",
                          yes_properties=("PID-332", "PID-3321")),
                 Question("plaintext", "Does any of its traffic go unencrypted "
                          "(ROS 1, MQTT without TLS, Telnet, plain HTTP)?",
                          yes_properties=("PID-411", "PID-4111", "PID-4112")),
                 Question("teleop", "Can it be driven or controlled remotely through a cloud service?",
                          yes_tags=("cloud-teleop",), yes_properties=("PID-411",)),
             )),
    Question("bluetooth", "Bluetooth or BLE (including for Wi-Fi setup / pairing)?",
             yes_tags=("bluetooth",), yes_properties=("PID-41",)),
    Question("updates", "Can its software or firmware be updated?",
             yes_properties=("PID-27",), no_properties=("PID-26",),
             followups=(
                 Question("ota", "Remotely, over the air?", yes_properties=("PID-275",)),
                 Question("signed", "Are updates cryptographically signed and checked before install?",
                          yes_properties=("PID-2722",), no_properties=("PID-271",)),
             )),
    Question("debug_port", "Is a debug port (UART, JTAG, SWD) reachable on the hardware?",
             yes_properties=("PID-15",)),
    Question("usb", "Does it have USB or serial ports someone could plug into?",
             yes_properties=("PID-14",)),
    Question("containers", "Does it run software in containers (Docker, etc.)?",
             yes_properties=("PID-24", "PID-241")),
    Question("custom_programs", "Can users upload their own programs, scripts or motion "
             "routines to it (e.g. URScript, ROS packages)?",
             yes_properties=("PID-32", "PID-322")),
    Question("native_code", "Is any of its software written in C or C++?",
             yes_properties=("PID-312", "PID-3122")),
    Question("ml", "Does it run ML models or learned policies on the device?",
             yes_tags=("ml",)),
)


# --------------------------------------------------------------------------
# SBOM component hints
# --------------------------------------------------------------------------

# Regex on a component name -> (tags, EMB3D properties). Matched case-insensitively.
COMPONENT_HINTS: tuple[tuple[re.Pattern[str], tuple[str, ...], tuple[str, ...]], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), tags, props)
    for pattern, tags, props in [
        (r"^lerobot$", ("lerobot", "ml"), ("PID-3121",)),
        (r"^(rclpy|rclcpp|rospy|roscpp|rosbag2?|ros-[a-z]+-.+)$", ("ros",), ("PID-41",)),
        (r"^(rosbridge[-_].+|roslibpy)$", ("rosbridge", "ros"), ("PID-41", "PID-311")),
        (r"^(torch|pytorch|tensorflow|tflite.*|onnxruntime.*|transformers|jax)$", ("ml",), ()),
        (r"^(paho-mqtt|mosquitto|aiomqtt|gmqtt)$", ("mqtt",), ("PID-41",)),
        (r"^(bluez|bleak|pybluez|bluepy)$", ("bluetooth",), ("PID-41",)),
        (r"^(flask|fastapi|django|aiohttp|nginx|lighttpd|express)$", (), ("PID-311", "PID-33")),
        (r"^(ur[-_]rtde|ur[-_]dashboard.*|polyscope.*)$", ("universal-robots",), ()),
        (r"^unitree[-_].+$", ("unitree",), ()),
    ]
)

# --------------------------------------------------------------------------
# Network port hints (scan-detect)
# --------------------------------------------------------------------------

# Port -> (label, tags, EMB3D properties). Any open port also implies PID-41,
# and any open port that doesn't speak TLS implies PID-4112 (see device_profile.py).
# Plain-language titles and diagram parts for robot findings (glitched.findings).
# Passive check (EMB3D threat it tests) -> (title, part).
CHECK_FINDINGS: dict[str, tuple[str, str]] = {
    "TID-406": ("Missing authentication", "network"),
    "TID-408": ("Unencrypted communication", "network"),
    "TID-411": ("Weak encryption (old TLS)", "network"),
}

# What each check's recheck sends, in plain words (shown while it runs).
CHECK_ACTIVITY: dict[str, str] = {
    "TID-406": "Sending one unauthenticated GET / to each web port…",
    "TID-408": "Connecting to common ports and reading each service's greeting…",
    "TID-411": "Starting a TLS handshake on each open port…",
}

# Check-specific fixes, for robotics engineers rather than security specialists.
CHECK_FIXES: dict[str, str] = {
    "TID-406": "Put a login in front of it, and only accept connections from the operator network.",
    "TID-408": "Turn off plaintext services you don't need (Telnet, plain HTTP); put the rest behind TLS "
               "(HTTPS, MQTT over TLS on 8883, rosbridge over wss) or reach them through SSH or a VPN.",
    "TID-411": "Allow only TLS 1.2 and newer in each service's TLS settings, and update the libraries "
               "that negotiate older versions.",
}

# The open-rosbridge fix depends on the ROS generation: only ROS 1's rosbridge
# has a built-in login (rosauth); ROS 2's has none.
ROSBRIDGE_FIXES: dict[int, str] = {
    1: "Turn on rosbridge's login (authenticate:=true, with rosauth) and only accept connections from the "
       "operator network.",
    2: "Bind rosbridge to the robot itself (address:=127.0.0.1) and reach it through a VPN or SSH tunnel - "
       "ROS 2's rosbridge has no login of its own.",
}

DECLARED_FIXES: dict[str, str] = {
    "PID-15": "Disable or fuse off UART/JTAG/SWD on production units, or put it behind a locked case and "
              "require authentication on the debug console.",
    "PID-331": "Put authentication in front of every service, or bind it to localhost and reach it "
               "through SSH or a VPN.",
    "PID-4111": "Use protocols that authenticate messages (e.g. SROS 2 for ROS 2, TLS with client "
                "certificates for MQTT).",
    "PID-4112": "Encrypt traffic in transit: TLS for web, MQTT and rosbridge; SROS 2 for ROS 2.",
    "PID-271": "Sign firmware and software updates and verify the signature on the robot before installing.",
    "PID-26": "Plan a way to ship security updates (signed, over the air or by service visit); until "
              "then, isolate the robot on its own network.",
}

# EMB3D properties that are a weakness in themselves when the profile declares
# them -> (title, part). The rest only make threats possible.
# How serious a declared weakness is on its own (see glitched.findings.severity).
DECLARED_SEVERITY: dict[str, str] = {
    "PID-331": "high", "PID-271": "high",
    "PID-15": "medium", "PID-4111": "medium", "PID-4112": "medium", "PID-26": "medium",
}

DECLARED_FINDINGS: dict[str, tuple[str, str]] = {
    "PID-15": ("Exposed debug interface", "debug_port"),
    "PID-331": ("Services reachable without logging in", "network"),
    "PID-4111": ("Messages aren't authenticated", "network"),
    "PID-4112": ("Traffic isn't encrypted", "network"),
    "PID-271": ("Updates aren't signed", "cloud_link"),
    "PID-26": ("Can't be updated", "whole_robot"),
}

# Protocols on these ports carry data in the clear unless wrapped in TLS. Any
# other port that doesn't speak TLS (or SSH) is "unknown", not plaintext.
PLAINTEXT_PORTS = {23, 80, 8080, 1883, 554, 5683, 9090, 11311}

PORT_HINTS: dict[int, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    11311: ("ROS 1 master", ("ros",), ("PID-331",)),
    9090: ("rosbridge", ("rosbridge", "ros"), ("PID-311",)),
    29999: ("Universal Robots dashboard server", ("universal-robots",), ("PID-331",)),
    1883: ("MQTT", ("mqtt",), ()),
    8883: ("MQTT over TLS", ("mqtt",), ("PID-4113",)),
    23: ("Telnet", ("telnet",), ("PID-332", "PID-3321")),
    22: ("SSH", (), ("PID-332",)),
    2222: ("SSH (alt)", (), ("PID-332",)),
    80: ("HTTP", (), ("PID-311", "PID-33")),
    8080: ("HTTP (alt)", (), ("PID-311", "PID-33")),
    443: ("HTTPS", (), ("PID-311", "PID-33", "PID-4113")),
    8443: ("HTTPS (alt)", (), ("PID-311", "PID-33", "PID-4113")),
    554: ("RTSP camera stream", ("rtsp",), ("PID-411",)),
    5683: ("CoAP", ("coap",), ()),
}
