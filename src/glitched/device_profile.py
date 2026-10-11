"""
Device profile: what a robot / IoT device is built from, in the customer's terms.

A profile is the single input to exposure matching (queries.get_exposure). It
lives in a `glitch.yaml` the team can check into their repo, and can be filled
in four ways - all of which produce a DeviceProfile and merge into the file:

  - from_questionnaire()   plain-language yes/no questions (catalog.QUESTIONS)
  - from_sbom(path)        CycloneDX or SPDX JSON software bill of materials
  - from_probes(probes)    open ports seen by a connect-only scan (glitched
                           does the probing; this only interprets the results)
  - load(path)             a hand-written glitch.yaml

    name: warehouse-amr-v3
    platforms: [ros, unitree]
    interfaces: [wifi, bluetooth, mqtt]
    ml: true
    components:
      - {name: lerobot, version: "0.2.1", ecosystem: pypi}
    properties: [PID-41, PID-4112, PID-275]
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from glitched import catalog
from glitched import ui

DEFAULT_PROFILE_PATH = Path("glitch.yaml")


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None = None
    ecosystem: str | None = None


@dataclass
class DeviceProfile:
    name: str
    platforms: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    ml: bool = False
    components: list[Component] = field(default_factory=list)
    properties: list[str] = field(default_factory=list)
    ros_distro: str | None = None  # e.g. "humble"; decides which core ROS CVEs apply

    @property
    def tags(self) -> list[str]:
        """Every tag the profile matches CVEs on."""
        return sorted(set(self.platforms) | set(self.interfaces) | ({"ml"} if self.ml else set()))

    def add_tags(self, tags: list[str] | tuple[str, ...]) -> None:
        """Sort tags into platforms / interfaces / ml; unknown tags count as interfaces."""
        for tag in tags:
            if tag == "ml":
                self.ml = True
            elif tag in catalog.PLATFORMS:
                _add(self.platforms, tag)
            else:
                _add(self.interfaces, tag)

    def add_properties(self, property_ids: list[str] | tuple[str, ...]) -> None:
        for pid in property_ids:
            _add(self.properties, pid)

    def merge(self, other: DeviceProfile) -> DeviceProfile:
        """Combine two profiles. Never removes anything; keeps this profile's name."""
        merged = DeviceProfile.from_dict(self.to_dict())
        merged.add_tags(other.tags)
        merged.add_properties(other.properties)
        known = {(c.name, c.version) for c in merged.components}
        merged.components += [c for c in other.components if (c.name, c.version) not in known]
        merged.ros_distro = merged.ros_distro or other.ros_distro
        return merged

    # ---- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["platforms"] = sorted(self.platforms)
        data["interfaces"] = sorted(self.interfaces)
        data["properties"] = sorted(self.properties)
        data["components"] = [
            {k: v for k, v in asdict(c).items() if v is not None} for c in self.components
        ]
        if self.ros_distro is None:
            del data["ros_distro"]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceProfile:
        if not data.get("name"):
            raise ValueError("profile needs a `name`")
        profile = cls(name=str(data["name"]))
        # Run declared platforms/interfaces through the keyword map too, so
        # people can write `ROS 2` or `Wi-Fi` and still match.
        for key in ("platforms", "interfaces"):
            for value in data.get(key) or []:
                profile.add_tags(catalog.infer_tags(str(value)) or [str(value).lower()])
        if data.get("ml"):
            profile.ml = True
        profile.components = [
            Component(name=str(c["name"]), version=_str_or_none(c.get("version")),
                      ecosystem=_str_or_none(c.get("ecosystem")))
            for c in data.get("components") or []
        ]
        profile.add_properties([str(p).upper() for p in data.get("properties") or []])
        distro = str(data.get("ros_distro") or "").strip().lower().split()[0] if data.get("ros_distro") else None
        if distro and distro not in catalog.ROS_DISTROS:
            raise ValueError(f"unknown ros_distro {data['ros_distro']!r}; one of: {', '.join(catalog.ROS_DISTROS)}")
        profile.ros_distro = distro
        return profile

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)

    @classmethod
    def from_yaml(cls, text: str) -> DeviceProfile:
        return cls.from_dict(yaml.safe_load(text) or {})


def load(path: Path = DEFAULT_PROFILE_PATH) -> DeviceProfile:
    if not path.exists():
        raise SystemExit(f"no profile at {path} - run `glitched onboard` first")
    return DeviceProfile.from_yaml(path.read_text())


def save(profile: DeviceProfile, path: Path = DEFAULT_PROFILE_PATH) -> None:
    path.write_text(profile.to_yaml())


# --------------------------------------------------------------------------
# Input: questionnaire
# --------------------------------------------------------------------------


def from_questionnaire(name: str) -> DeviceProfile:
    """Ask plain-language questions; map answers to tags + EMB3D properties."""
    profile = DeviceProfile(name=name)

    profile.add_tags(ui.checkbox(
        "Which of these is it built on? (none is fine)",
        [(label, key) for key, label in catalog.PLATFORMS.items()],
    ))

    if "ros" in profile.platforms:
        profile.ros_distro = ui.select(
            "Which ROS distro does it run?",
            [("Not sure", None)] + [(f"ROS {gen} {d.capitalize()}", d)
                                    for d, gen in reversed(list(catalog.ROS_DISTROS.items()))],
            default=None,
        )

    for question in catalog.QUESTIONS:
        _ask(question, profile, indent="")

    if "PID-41" in profile.properties:
        profile.add_tags(ui.checkbox(
            "Which of these does it use to talk to other systems?",
            [(label, key) for key, label in catalog.INTERFACES.items()],
            checked=profile.interfaces,
        ))
    return profile


def _walk(questions: tuple[catalog.Question, ...] = catalog.QUESTIONS):
    for question in questions:
        yield question
        yield from _walk(question.followups)


def question_controlled() -> tuple[set[str], set[str]]:
    """Every tag and property the questionnaire (and platform/interface choices) can set."""
    tags = set(catalog.PLATFORMS) | set(catalog.INTERFACES)
    properties: set[str] = set()
    for q in _walk():
        tags |= set(q.yes_tags)
        properties |= set(q.yes_properties) | set(q.no_properties)
    return tags, properties


def apply_answers(profile: DeviceProfile, platforms: list[str], answers: dict[str, bool],
                  interfaces: list[str], ros_distro: str | None = None) -> DeviceProfile:
    """
    The questionnaire without prompts (for the UI): replace everything the
    questions control with these answers, keeping what came from elsewhere
    (SBOM components and hints, detected services). Follow-up answers only
    count when their question was answered yes, exactly as when asked.
    """
    unknown = set(platforms) - set(catalog.PLATFORMS)
    unknown |= set(interfaces) - set(catalog.INTERFACES)
    unknown |= set(answers) - {q.key for q in _walk()}
    if ros_distro and ros_distro not in catalog.ROS_DISTROS:
        unknown.add(ros_distro)
    if unknown:
        raise SystemExit(f"unknown answer(s): {', '.join(sorted(unknown))}")
    tags, properties = question_controlled()
    fresh = DeviceProfile(
        name=profile.name,
        platforms=[t for t in profile.platforms if t not in tags],
        interfaces=[t for t in profile.interfaces if t not in tags],
        ml=False,
        components=list(profile.components),
        properties=[p for p in profile.properties if p not in properties],
        ros_distro=ros_distro if "ros" in platforms else None,
    )
    fresh.add_tags(platforms)

    def answer(question: catalog.Question) -> None:
        if answers.get(question.key):
            fresh.add_tags(question.yes_tags)
            fresh.add_properties(question.yes_properties)
            for followup in question.followups:
                answer(followup)
        else:
            fresh.add_properties(question.no_properties)

    for question in catalog.QUESTIONS:
        answer(question)
    if "PID-41" in fresh.properties:
        fresh.add_tags(interfaces)
    return fresh  # "ml" is a question too, so the answer decides it


def answers_from(profile: DeviceProfile) -> dict[str, Any]:
    """Read the questionnaire's answers back out of a profile (to edit them in the UI)."""
    tags = set(profile.tags)
    props = set(profile.properties)
    answers = {}
    for q in _walk():
        said_yes = (set(q.yes_tags) <= tags and set(q.yes_properties) <= props
                    and bool(q.yes_tags or q.yes_properties))
        answers[q.key] = said_yes
    return {
        "platforms": [p for p in profile.platforms if p in catalog.PLATFORMS],
        "interfaces": [i for i in profile.interfaces if i in catalog.INTERFACES],
        "answers": answers,
        "ros_distro": profile.ros_distro,
    }


def questionnaire() -> dict[str, Any]:
    """The questions, platforms and interfaces, for the UI to render."""
    def q(question: catalog.Question) -> dict[str, Any]:
        return {"key": question.key, "prompt": question.prompt,
                "followups": [q(f) for f in question.followups]}

    return {"platforms": catalog.PLATFORMS, "interfaces": catalog.INTERFACES,
            "ros_distros": [{"id": d, "label": f"ROS {gen} {d.capitalize()}"}
                            for d, gen in reversed(list(catalog.ROS_DISTROS.items()))],
            "questions": [q(question) for question in catalog.QUESTIONS]}


def _ask(question: catalog.Question, profile: DeviceProfile, indent: str) -> None:
    if ui.confirm(f"{indent}{question.prompt}", default=False):
        profile.add_tags(question.yes_tags)
        profile.add_properties(question.yes_properties)
        for followup in question.followups:
            _ask(followup, profile, indent=indent + "  ")
    else:
        profile.add_properties(question.no_properties)


# --------------------------------------------------------------------------
# Input: SBOM
# --------------------------------------------------------------------------


def from_sbom(path: Path, name: str) -> DeviceProfile:
    """Read a CycloneDX/SPDX JSON SBOM, or a package list (see from_package_list)."""
    text = path.read_text(errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return from_package_list(text, name)
    return from_sbom_data(data, name, str(path))


_DPKG_L = re.compile(r"^[ih]i\s+(\S+)\s+(\S+)\s")   # dpkg -l, installed only: "ii  name  version  arch  desc"
_DPKG_OTHER = re.compile(r"^[a-z][a-zA-Z]\s+\S+\s+\S+\s")     # dpkg -l rows for removed packages (rc, un, ...)
_TABBED = re.compile(r"^([A-Za-z0-9][\w.+:-]*)\t+(\S+)\s*$")     # dpkg-query -W: "name<TAB>version"
_PIP = re.compile(r"^([A-Za-z0-9][\w.-]*)\s*==\s*(\S+)\s*$")       # pip freeze: "name==version"
_NAME = re.compile(r"^([a-z0-9][a-z0-9_.+-]*)$")                   # ros2 pkg list: one name per line


def debian_upstream(version: str) -> str:
    """1:1.3.11-1jammy.20240101 -> 1.3.11 (drop the epoch and the Debian revision)."""
    version = version.split(":", 1)[1] if re.match(r"^\d+:", version) else version
    return version.rsplit("-", 1)[0] if "-" in version else version


def from_package_list(text: str, name: str) -> DeviceProfile:
    """
    Components from what an engineer can get off a robot in seconds:
    `dpkg-query -W`, `dpkg -l`, `pip freeze` or `ros2 pkg list` output.
    Versions from Debian packages are compared by their upstream part.
    """
    profile = DeviceProfile(name=name)
    seen: set[tuple[str, str | None]] = set()
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith(("#", "Desired=", "|", "+++", "||/")):
            continue
        if m := _DPKG_L.match(line):
            comp, version, ecosystem = m.group(1).split(":")[0], debian_upstream(m.group(2)), "deb"
        elif _DPKG_OTHER.match(line):
            continue  # removed, or only config files left
        elif m := _TABBED.match(line):
            comp, version, ecosystem = m.group(1).split(":")[0], debian_upstream(m.group(2)), "deb"
        elif m := _PIP.match(line):
            comp, version, ecosystem = m.group(1), m.group(2), "pypi"
        elif m := _NAME.match(line.strip()):
            comp, version, ecosystem = m.group(1), None, "ros"
        else:
            continue
        if (comp, version) in seen:
            continue
        seen.add((comp, version))
        profile.components.append(Component(name=comp, version=version, ecosystem=ecosystem))
        for pattern, tags, props in catalog.COMPONENT_HINTS:
            if pattern.match(comp):
                profile.add_tags(tags)
                profile.add_properties(props)
    if not profile.components:
        raise SystemExit("Couldn't read any packages. Use the output of `dpkg-query -W`, `dpkg -l`, `pip freeze` "
                         "or `ros2 pkg list`, or a CycloneDX/SPDX JSON SBOM.")
    return profile


def from_sbom_data(data: Any, name: str, path: str = "the SBOM") -> DeviceProfile:
    """from_sbom for already-parsed JSON (e.g. an upload in the UI)."""
    if not isinstance(data, dict):
        raise SystemExit(f"{path} is not a CycloneDX or SPDX JSON SBOM")
    # Hardware entries (CycloneDX "device", SPDX DEVICE) aren't software; the console lists them as hardware.
    if data.get("bomFormat") == "CycloneDX":
        raw = [(c.get("name"), c.get("version"), c.get("purl")) for c in data.get("components", [])
               if c.get("type") != "device"]
    elif "spdxVersion" in data:
        raw = [
            (p.get("name"), p.get("versionInfo"), next(
                (r.get("referenceLocator") for r in p.get("externalRefs", [])
                 if r.get("referenceType") == "purl"),
                None,
            ))
            for p in data.get("packages", []) if p.get("primaryPackagePurpose") != "DEVICE"
        ]
    else:
        raise SystemExit(f"{path} is not a CycloneDX or SPDX JSON SBOM")

    profile = DeviceProfile(name=name)
    for comp_name, version, purl in raw:
        if not comp_name:
            continue
        profile.components.append(
            Component(name=comp_name, version=_str_or_none(version), ecosystem=_ecosystem(purl))
        )
        for pattern, tags, props in catalog.COMPONENT_HINTS:
            if pattern.match(comp_name):
                profile.add_tags(tags)
                profile.add_properties(props)
    return profile


def _ecosystem(purl: str | None) -> str | None:
    """pkg:pypi/lerobot@0.2.1 -> pypi"""
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0] or None


# --------------------------------------------------------------------------
# Input: scan-detect
# --------------------------------------------------------------------------


def from_probes(probes: list[dict], name: str) -> list[tuple[str, DeviceProfile]]:
    """
    Turn connect-only probe results (cli._probe_port dicts) into suggested
    profile additions, one per open port, each with a human-readable reason.
    The caller decides which to accept - nothing here is applied automatically.
    """
    suggestions = []
    for probe in probes:
        if not probe["open"]:
            continue
        port = probe["port"]
        label, tags, props = catalog.PORT_HINTS.get(port, (f"port {port}", (), ()))
        suggestion = DeviceProfile(name=name)
        suggestion.add_tags(tags)
        suggestion.add_properties(("PID-41",) + props)
        reason = f"{label} open on {port}"
        if probe.get("ssh"):
            reason += " (SSH, encrypted)"
        elif probe["tls"] is False and port in catalog.PLAINTEXT_PORTS:
            suggestion.add_properties(("PID-4112",))
            reason += " (no TLS)"
        suggestions.append((reason, suggestion))
    return suggestions


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _add(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _str_or_none(value: Any) -> str | None:
    return None if value is None else str(value)
