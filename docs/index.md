# What is Glitched?

Glitched is security testing for robots. It tells you which known weaknesses
affect a robot from a description of it, checks them on the robot with
passive, connect-only probes, and keeps each problem tracked from found to fixed.
It runs on robots you own or are authorized to test.

It's open source (Apache-2.0) and runs on your own machine:

- **The command line** (`glitched`): describe a robot, see what applies, scan it, and
  work through its findings. `glitched ui` shows the same in your browser, on
  `127.0.0.1` only.
- **The runner** (`glitched-runner`): a small, dependency-free scanner that runs inside the
  robots' network, probes only what its own local policy file allows, and connects
  *out* to a Glitched console. You can read exactly what it does in
  [`src/glitched/runner`](../src/glitched/runner).

## The problem

Robots combine an operating system, middleware like ROS, vendor SDKs, network
services, debug ports, cloud links and, more and more, machine-learning models. The
weaknesses that matter are spread across sources that don't talk to each other:

- **MITRE EMB3D** describes threats to embedded devices, by device property.
- **NIST's NVD** lists CVEs, and CISA's catalogue says which are exploited in the wild.
- **MITRE ATLAS** describes attacks on AI systems and real incidents.

Glitched joins them, and matches them to *your* robot's parts, software and
connections, rather than to a generic product name.

## Who is it for?

- **Robotics engineers** who want to know what affects the robot they're building, and
  fix it before it ships.
- **Security teams** responsible for a fleet: what's exposed, how badly, and what to
  fix first.
- **Platform teams** who want security in CI: fail a build when a robot's code picks up
  a serious, known vulnerability.

## How does it work?

### Describe

Answer about fifteen plain questions (`glitched onboard`), or import an SBOM or a
package list from the robot. The result is a device profile (`glitch.yaml`): the
robot's platforms, interfaces, software and EMB3D properties.

### Match

Glitched lists the threats and CVEs that apply, each with *why* it applies. That might
be a platform it's built on, a component and version in its SBOM, or a property it
declared. For ROS robots, the ROS distribution decides which ROS CVEs apply.

### Verify

A scan sends passive, connect-only checks to one host: open ports, plaintext
protocols, weak TLS, and services that answer without a login. Anything intrusive is
listed for a person to do and record. Glitched never does it on its own.

### Track and fix

Every finding keeps its history, from found through fix applied to resolved, or accepted
with a reason and a review date. `glitched autoscan` re-checks registered devices on a
schedule and exits non-zero when something new is confirmed, so cron or CI can alert you.

## Get started

- **Start here:** [the command line](cli.md). Install, describe a robot, scan it.
- **Every command:** [CLI reference](cli-reference.md).
- **Contributing:** see [CONTRIBUTING.md](../CONTRIBUTING.md). Report security issues
  privately, as [SECURITY.md](../SECURITY.md) describes.
