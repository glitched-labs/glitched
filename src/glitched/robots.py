"""
Robot details shared by the local UI (glitched.web) and the hosted console:
checking the add-robot form, building a profile from its answers, reading a
software list or SBOM, and storing a robot's profile.

No web framework and no name lookups: a robot's profile is stored against
the robot itself, so two organisations' "turtlebot"s never meet.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from psycopg2.extensions import cursor as Cursor

from glitched import device_profile, targets
from glitched.device_profile import DeviceProfile

MAX_NAME = 60
MAX_SOFTWARE_BYTES = 10 * 1024 * 1024
PROPERTY_ID = re.compile(r"PID-\d+")


class RobotError(Exception):
    """A problem with what the user sent; `field` names the form field when there is one."""

    def __init__(self, message: str, field: str | None = None, code: str | None = None):
        super().__init__(message)
        self.message, self.field, self.code = message, field, code


@dataclass(frozen=True)
class NewRobot:
    name: str
    host: str | None  # None: no network address yet (console only; the local app always needs one)
    authorization: str
    every_hours: int
    template: str | None


def check_new_robot(body: dict[str, Any], require_authorization: bool = True, require_host: bool = True) -> NewRobot:
    """
    The add-robot form's fields, checked (the host's address is checked by the
    caller). The console asks for the authorization later, with the testing scope.
    """
    name = str(body.get("name") or "").strip()
    authorization = str(body.get("authorization") or "").strip()
    if not name or len(name) > MAX_NAME:
        raise RobotError(f"Give the robot a name (up to {MAX_NAME} characters).", field="name")
    if not authorization and require_authorization:
        raise RobotError("Say why you're allowed to test this robot (e.g. “I own it”).", field="authorization")
    if len(authorization) > 500:
        raise RobotError("Keep the authorization note under 500 characters.", field="authorization")
    every = body.get("every_hours", 24)
    if not isinstance(every, int) or isinstance(every, bool) or not 1 <= every <= 24 * 365:
        raise RobotError("Scan interval must be a whole number of hours.", field="every_hours")
    host = check_host(body.get("host"), required=require_host)
    template = body.get("template")
    return NewRobot(name, host, authorization, every, str(template) if template else None)


def check_host(value: Any, required: bool = True) -> str | None:
    """A robot's address: one IP address or host name. Empty is None when an address isn't required."""
    text = str(value or "").strip()
    if not text and not required:
        return None
    try:
        host = targets.validate_single_host(text)
    except ValueError as exc:
        raise RobotError(str(exc), field="host") from None
    if len(host) > 253:
        raise RobotError("That host name is too long.", field="host")
    return host


def profile_from(body: dict[str, Any], base: DeviceProfile) -> DeviceProfile:
    """Apply the form's platforms, interfaces, answers and ROS distro to a profile."""
    platforms, interfaces, answers = body.get("platforms", []), body.get("interfaces", []), body.get("answers", {})
    if not (isinstance(platforms, list) and isinstance(interfaces, list) and isinstance(answers, dict)):
        raise RobotError("platforms and interfaces are lists; answers is an object")
    try:
        distro = body.get("ros_distro") or None
        return device_profile.apply_answers(base, [str(p) for p in platforms],
                                            {str(k): v is True for k, v in answers.items()},
                                            [str(i) for i in interfaces],
                                            str(distro) if distro else None)
    except SystemExit as exc:
        raise RobotError(str(exc.code)) from None


def software_from(data: bytes, profile: DeviceProfile) -> DeviceProfile:
    """
    Read a software list: a CycloneDX/SPDX SBOM (JSON), or a package list
    (dpkg-query -W, dpkg -l, pip freeze, ros2 pkg list). Returns the profile
    with what it found merged in.
    """
    if len(data) > MAX_SOFTWARE_BYTES:
        raise RobotError("That file is larger than 10 MB.")
    if b"\x00" in data:
        raise RobotError("That isn't a software list (it's a binary file). Upload an SBOM (JSON) or a package list.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RobotError("That isn't a software list (not UTF-8 text).") from None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None  # not JSON: a package list
    try:
        found = (device_profile.from_sbom_data(parsed, profile.name) if parsed is not None
                 else device_profile.from_package_list(text, profile.name))
        return profile.merge(found)
    except SystemExit as exc:
        raise RobotError(str(exc.code)) from None


def profile_of(cur: Cursor, device_id: int) -> DeviceProfile | None:
    """The robot's stored profile; None if it has none (CLI devices may not)."""
    cur.execute("SELECT d.name, p.yaml FROM devices d LEFT JOIN profiles p ON p.id = d.profile_id WHERE d.id = %s",
                (device_id,))
    row = cur.fetchone()
    if row is None:
        return None
    name, yaml_text = row
    return DeviceProfile.from_yaml(yaml_text) if yaml_text else DeviceProfile(name=name)


def store_profile(cur: Cursor, device_id: int, profile: DeviceProfile) -> int:
    """
    Save a robot's profile and its EMB3D properties, against the robot: its
    current profile row is updated, or a new one is made and linked. Used
    where profiles aren't keyed by name (the console); the local CLI's
    profiles are, so it keeps cli._store_profile. Returns the profile id.
    """
    bad = [p for p in profile.properties if not PROPERTY_ID.fullmatch(p)]
    if bad:
        raise RobotError(f"unknown EMB3D property ids: {bad}")
    cur.execute("SELECT profile_id FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    profile_id = row[0] if row else None
    if profile_id is None:
        cur.execute("INSERT INTO profiles (name, yaml) VALUES (%s, %s) RETURNING id", (profile.name, profile.to_yaml()))
        profile_id = cur.fetchone()[0]
        cur.execute("UPDATE devices SET profile_id = %s WHERE id = %s", (profile_id, device_id))
    else:
        cur.execute("UPDATE profiles SET yaml = %s, updated_at = now() WHERE id = %s", (profile.to_yaml(), profile_id))
    cur.execute("DELETE FROM profile_properties WHERE profile_id = %s", (profile_id,))
    for pid in profile.properties:
        cur.execute("INSERT INTO profile_properties (profile_id, property_id) VALUES (%s, %s)", (profile_id, pid))
    return profile_id


def profile_view(profile: DeviceProfile) -> dict[str, Any]:
    """What the robot form shows: its answers, components and properties."""
    return {**device_profile.answers_from(profile),
            "components": [{"name": c.name, "version": c.version} for c in profile.components],
            "properties": profile.properties}
