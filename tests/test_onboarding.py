"""Unit tests for the onboarding vocabulary and device profiles (no DB needed).

    python -m unittest tests.test_onboarding
"""

import json
import tempfile
import unittest
from pathlib import Path

from glitched import catalog
from glitched import device_profile
from glitched.device_profile import DeviceProfile


class InferTagsTest(unittest.TestCase):
    def test_whole_words_only(self):
        # Substring matching used to tag these as bluetooth / ros.
        self.assertEqual(catalog.infer_tags("a vulnerable table across the fleet"), [])

    def test_real_cve_text(self):
        text = "Root command injection in Unitree Go2 firmware via BLE WiFi configuration"
        self.assertEqual(
            catalog.infer_tags(text),
            ["bluetooth", "command-injection", "firmware", "unitree", "wifi"],
        )

    def test_ros_in_parentheses(self):
        self.assertEqual(catalog.infer_tags("Robot Operating System (ROS) rosparam"), ["ros"])


class SbomTest(unittest.TestCase):
    def _write(self, data: dict) -> Path:
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return Path(f.name)

    def test_cyclonedx(self):
        path = self._write({
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "lerobot", "version": "0.2.1", "purl": "pkg:pypi/lerobot@0.2.1"},
                {"name": "paho-mqtt", "version": "2.1.0"},
                {"name": "numpy", "version": "2.0.0"},
            ],
        })
        profile = device_profile.from_sbom(path, "bot")
        self.assertEqual(profile.platforms, ["lerobot"])
        self.assertEqual(profile.interfaces, ["mqtt"])
        self.assertTrue(profile.ml)
        self.assertIn("PID-41", profile.properties)
        self.assertEqual(profile.components[0].ecosystem, "pypi")
        self.assertEqual(len(profile.components), 3)

    def test_spdx(self):
        path = self._write({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "ros-humble-rclcpp", "versionInfo": "16.0.0",
                "externalRefs": [{"referenceType": "purl",
                                  "referenceLocator": "pkg:deb/ros-humble-rclcpp@16.0.0"}],
            }],
        })
        profile = device_profile.from_sbom(path, "bot")
        self.assertEqual(profile.platforms, ["ros"])
        self.assertEqual(profile.components[0].ecosystem, "deb")


class ProbeTest(unittest.TestCase):
    def test_rosbridge_without_tls(self):
        probes = [
            {"port": 9090, "open": True, "tls": False, "banner": ""},
            {"port": 22, "open": False, "tls": None, "banner": ""},
        ]
        [(reason, suggestion)] = device_profile.from_probes(probes, "bot")
        self.assertIn("rosbridge", reason)
        self.assertEqual(suggestion.platforms, ["ros"])
        self.assertIn("rosbridge", suggestion.interfaces)
        self.assertTrue({"PID-41", "PID-311", "PID-4112"} <= set(suggestion.properties))


class ProfileTest(unittest.TestCase):
    def test_yaml_round_trip_normalises_names(self):
        profile = DeviceProfile.from_yaml(
            "name: amr\nplatforms: [ROS 2, Unitree]\ninterfaces: [Wi-Fi]\nml: true\n"
            "properties: [pid-41]\n"
        )
        self.assertEqual(profile.platforms, ["ros", "unitree"])
        self.assertEqual(profile.interfaces, ["wifi"])
        self.assertEqual(profile.properties, ["PID-41"])
        self.assertEqual(DeviceProfile.from_yaml(profile.to_yaml()), profile)

    def test_merge_never_removes(self):
        a = DeviceProfile(name="amr", platforms=["ros"], properties=["PID-41"])
        b = DeviceProfile(name="other", interfaces=["wifi"], properties=["PID-15"])
        merged = a.merge(b)
        self.assertEqual(merged.name, "amr")
        self.assertEqual(merged.tags, ["ros", "wifi"])
        self.assertEqual(merged.properties, ["PID-41", "PID-15"])
        self.assertEqual(a.tags, ["ros"])  # inputs untouched



class AnswersTest(unittest.TestCase):
    """The questionnaire without prompts (the UI's add/edit robot form)."""

    def test_answers_round_trip(self):
        answers = {"os": True, "network": True, "wifi": True, "web": True, "updates": True,
                   "ota": True, "signed": False, "debug_port": True}
        profile = device_profile.apply_answers(DeviceProfile(name="bot"), ["ros"], answers, ["mqtt"])
        back = device_profile.answers_from(profile)
        self.assertEqual({k for k, v in back["answers"].items() if v},
                         {"os", "network", "wifi", "web", "updates", "ota", "debug_port"})
        self.assertEqual(back["platforms"], ["ros"])
        self.assertEqual(set(back["interfaces"]), {"wifi", "mqtt"})
        self.assertIn("PID-271", profile.properties)  # "not signed" is a property too

    def test_followups_only_count_after_yes(self):
        profile = device_profile.apply_answers(DeviceProfile(name="bot"), [], {"network": False, "web": True}, [])
        self.assertNotIn("PID-311", profile.properties)

    def test_changing_answers_keeps_sbom_and_detected_details(self):
        start = DeviceProfile(name="bot", properties=["PID-3121", "PID-15"],
                              components=[device_profile.Component("mosquitto", "2.0.18", "deb")])
        changed = device_profile.apply_answers(start, [], {"debug_port": False}, [])
        self.assertIn("PID-3121", changed.properties)      # from an SBOM hint: kept
        self.assertNotIn("PID-15", changed.properties)     # the debug-port answer changed: removed
        self.assertEqual(len(changed.components), 1)

    def test_ros_distro_round_trip(self):
        profile = device_profile.apply_answers(DeviceProfile(name="bot"), ["ros"], {}, [], ros_distro="humble")
        self.assertEqual(device_profile.answers_from(profile)["ros_distro"], "humble")
        self.assertEqual(DeviceProfile.from_yaml(profile.to_yaml()).ros_distro, "humble")
        not_ros = device_profile.apply_answers(profile, [], {}, [], ros_distro="humble")
        self.assertIsNone(not_ros.ros_distro)  # only kept while built on ROS
        with self.assertRaises(ValueError):
            DeviceProfile.from_yaml("name: bot\nros_distro: banana\n")

    def test_unknown_answers_are_refused(self):
        with self.assertRaises(SystemExit):
            device_profile.apply_answers(DeviceProfile(name="bot"), ["not-a-platform"], {}, [])
        with self.assertRaises(SystemExit):
            device_profile.apply_answers(DeviceProfile(name="bot"), [], {"made_up": True}, [])

    def test_package_lists(self):
        dpkg_query = "mosquitto\t1.4.10-1\nros-humble-nav2-planner\t1.1.12-1jammy.20240101\nlibssl3:arm64\t3.0.2-0ubuntu1\n"
        dpkg_l = ("Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name Version Architecture Description\n+++-===\n"
                  "ii  mosquitto  1:2.0.18-1  arm64  MQTT broker\nrc  oldpkg  1.0  all  removed, config left\n")
        cases = {
            dpkg_query: [("mosquitto", "1.4.10"), ("ros-humble-nav2-planner", "1.1.12"), ("libssl3", "3.0.2")],
            dpkg_l: [("mosquitto", "2.0.18")],
            "paho-mqtt==1.6.1\n": [("paho-mqtt", "1.6.1")],
            "nav2_bringup\nrclcpp\n": [("nav2_bringup", None), ("rclcpp", None)],
        }
        for text, expected in cases.items():
            profile = device_profile.from_package_list(text, "bot")
            self.assertEqual([(c.name, c.version) for c in profile.components], expected)

    def test_debian_versions_compare_by_upstream(self):
        self.assertEqual(device_profile.debian_upstream("1:1.3.11-1jammy.20240101"), "1.3.11")
        self.assertEqual(device_profile.debian_upstream("2.0.18"), "2.0.18")

    def test_unreadable_lists_are_refused(self):
        with self.assertRaises(SystemExit):
            device_profile.from_package_list("Hello, this is not a package list!\n", "bot")

    def test_sbom_from_uploaded_data(self):
        sbom = {"bomFormat": "CycloneDX", "components": [{"name": "mosquitto", "version": "1.4.10",
                                                          "purl": "pkg:deb/debian/mosquitto@1.4.10"}]}
        profile = device_profile.from_sbom_data(sbom, "bot")
        self.assertEqual([(c.name, c.version) for c in profile.components], [("mosquitto", "1.4.10")])
        with self.assertRaises(SystemExit):
            device_profile.from_sbom_data(["not", "an", "sbom"], "bot")

    def test_hardware_in_an_sbom_isnt_software(self):
        cyclonedx = {"bomFormat": "CycloneDX", "components": [
            {"type": "device", "name": "UR10e control box"},
            {"type": "firmware", "name": "PolyScope", "version": "5.15.2"},
            {"type": "library", "name": "openssl", "version": "3.0.2"}]}
        self.assertEqual([c.name for c in device_profile.from_sbom_data(cyclonedx, "bot").components],
                         ["PolyScope", "openssl"])  # firmware stays: it's software, and can have CVEs
        spdx = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "Jetson Orin NX", "primaryPackagePurpose": "DEVICE"},
            {"name": "zlib", "versionInfo": "1.3", "primaryPackagePurpose": "LIBRARY"}]}
        self.assertEqual([c.name for c in device_profile.from_sbom_data(spdx, "bot").components], ["zlib"])

if __name__ == "__main__":
    unittest.main()
