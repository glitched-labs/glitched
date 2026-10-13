"""
Which CVEs apply to a device: by platform or SBOM component (with NVD's
affected version ranges), never by a shared interface alone. No database: the
two queries are replaced with recorded rows.
"""

import unittest
from unittest import mock

from glitched import queries

NVD = [
    # Another vendor's Wi-Fi thermostat: shares only "wifi" with the device.
    {"id": "CVE-2022-43704", "score": 5.9, "description": "Sinilink WiFi thermostat ...",
     "platform_tags": ["wifi", "mqtt"], "kev": None},
    # Names the ROS platform.
    {"id": "CVE-2024-39289", "score": 9.8, "description": "Robot Operating System ...",
     "platform_tags": ["ros"], "kev": None},
    # ROS 2 navigation2 bug (product nav2), Siemens RUGGEDCOM "ROS" (a switch OS), a Unitree robot CVE.
    {"id": "CVE-2026-26011", "score": 7.5, "description": "navigation2 is a ROS 2 Navigation Framework. ...",
     "platform_tags": ["ros"], "kev": None},
    {"id": "CVE-2023-0001", "score": 9.8, "description": "RUGGEDCOM ROS before V5.8 ...",
     "platform_tags": ["ros"], "kev": None},
    {"id": "CVE-2025-0002", "score": 8.0, "description": "Unitree Go2 firmware ...",
     "platform_tags": ["unitree"], "kev": None},
    # Mosquitto, fixed in 1.4.12.
    {"id": "CVE-2017-7650", "score": 6.5, "description": "In Mosquitto before 1.4.12 ...",
     "platform_tags": ["mqtt"], "kev": None},
]
PRODUCTS = {
    "CVE-2024-39289": [{"vendor": "openrobotics", "product": "robot_operating_system", "version": v}
                       for v in ("noetic_ninjemys", "melodic_morenia")],
    "CVE-2026-26011": [{"vendor": "opennav", "product": "nav2", "version": None, "version_end_excluding": "1.3.12"}],
    "CVE-2023-0001": [{"vendor": "siemens", "product": "ruggedcom_rugged_operating_system", "version": None}],
    "CVE-2022-43704": [{"product": "xy-wft1_firmware", "version": "1.3.6"}],
    "CVE-2017-7650": [{"product": "mosquitto", "version": None,
                       "version_start_including": "1.4", "version_end_excluding": "1.4.12"}],
}


def exposure(tags, components=(), ros_distro=None):
    def tables_exist(tables, database_url):
        return tables == ["nvd_cves"]

    with mock.patch.object(queries, "tables_exist", side_effect=tables_exist), \
            mock.patch.object(queries, "query", return_value=NVD), \
            mock.patch.object(queries, "_affected_products", return_value=PRODUCTS):
        rows = queries._cve_exposure(set(tags), list(components), "postgresql://unused", ros_distro)
    return {r["ref_id"]: r for r in rows}


class CveMatchingTest(unittest.TestCase):
    def test_shared_interface_alone_is_only_related(self):
        rows = exposure({"wifi", "bluetooth"})
        self.assertEqual({k for k, r in rows.items() if not r["related"]}, set())
        self.assertIn("CVE-2022-43704", rows)
        self.assertTrue(rows["CVE-2022-43704"]["related"])

    def test_platform_applies(self):
        rows = exposure({"unitree", "wifi"})
        self.assertFalse(rows["CVE-2025-0002"]["related"])
        self.assertIn("Unitree", rows["CVE-2025-0002"]["reason"])

    def test_core_ros_applies_by_distro(self):
        rows = exposure({"ros"}, ros_distro="noetic")
        self.assertFalse(rows["CVE-2024-39289"]["related"])
        self.assertIn("ROS 1 (Noetic)", rows["CVE-2024-39289"]["reason"])
        self.assertNotIn("CVE-2024-39289", exposure({"ros"}, ros_distro="humble"))  # a ROS 1 bug on ROS 2

    def test_core_ros_without_a_distro_is_only_related(self):
        row = exposure({"ros"})["CVE-2024-39289"]
        self.assertTrue(row["related"])
        self.assertIn("ROS distro", row["reason"])

    def test_ros_package_cves_need_the_package_in_the_sbom(self):
        self.assertTrue(exposure({"ros"}, ros_distro="humble")["CVE-2026-26011"]["related"])
        rows = exposure({"ros"}, [("ros-humble-navigation2", "1.3.11")], ros_distro="humble")
        self.assertFalse(rows["CVE-2026-26011"]["related"])
        self.assertEqual(rows["CVE-2026-26011"]["fixed_in"], "1.3.12")
        self.assertNotIn("CVE-2026-26011", exposure({"ros"}, [("ros-humble-navigation2", "1.3.12")], "humble"))

    def test_package_bugs_filed_under_core_ros_need_the_package(self):
        products = [{"vendor": "openrobotics", "product": "robot_operating_system", "version": "2"}]
        description = "Insecure Permissions vulnerability in ROS2 navigation2 v.humble allows an attacker ..."
        self.assertEqual(queries.ros_match(products, "humble", description)[0], "related")
        self.assertEqual(queries.ros_match(products, "humble", "A flaw in ROS 2 core ...")[0], "applies")

    def test_ros2_pkg_list_names_match_their_family(self):
        rows = exposure({"ros"}, [("nav2_planner", None)], ros_distro="humble")
        self.assertFalse(rows["CVE-2026-26011"]["related"])
        self.assertIn("version not checked", rows["CVE-2026-26011"]["reason"])

    def test_other_products_called_ros_are_only_related(self):
        row = exposure({"ros"}, ros_distro="humble")["CVE-2023-0001"]
        self.assertTrue(row["related"])
        self.assertIn("another product", row["reason"])

    def test_component_in_range_is_affected(self):
        rows = exposure({"mqtt"}, [("mosquitto", "1.4.10")])
        self.assertFalse(rows["CVE-2017-7650"]["related"])
        self.assertIn("mosquitto 1.4.10 is listed as affected", rows["CVE-2017-7650"]["reason"])

    def test_component_out_of_range_is_dropped(self):
        rows = exposure({"mqtt"}, [("mosquitto", "2.0.18")])
        self.assertNotIn("CVE-2017-7650", rows)

    def test_component_without_version_is_unchecked(self):
        rows = exposure({"mqtt"}, [("Mosquitto", None)])
        self.assertIn("version not checked", rows["CVE-2017-7650"]["reason"])
        self.assertFalse(rows["CVE-2017-7650"]["related"])

    def test_component_matches_rank_above_platform_matches(self):
        rows = exposure({"ros", "mqtt"}, [("mosquitto", "1.4.10")], ros_distro="noetic")
        self.assertLess(rows["CVE-2017-7650"]["rank"], rows["CVE-2024-39289"]["rank"])


class VersionRangeTest(unittest.TestCase):
    def affected(self, version, **bounds):
        return queries.version_affected(version, {"version": None, **bounds})

    def test_bounds(self):
        self.assertTrue(self.affected("1.4.10", version_start_including="1.4", version_end_excluding="1.4.12"))
        self.assertFalse(self.affected("1.4.12", version_end_excluding="1.4.12"))
        self.assertTrue(self.affected("1.4.12", version_end_including="1.4.12"))
        self.assertFalse(self.affected("1.3.9", version_start_including="1.4"))
        self.assertFalse(self.affected("1.4", version_start_excluding="1.4"))
        self.assertTrue(self.affected("1.10.0", version_start_including="1.9"))  # numeric, not text order

    def test_exact_version(self):
        self.assertTrue(queries.version_affected("1.3.6", {"version": "1.3.6"}))
        self.assertFalse(queries.version_affected("1.3.7", {"version": "1.3.6"}))

    def test_names_compare_loosely(self):
        products = [{"product": "paho_mqtt", "version": "1.6.1"}]
        self.assertEqual(queries.component_match(products, [("paho-mqtt", "1.6.1")]),
                         ("paho-mqtt 1.6.1", "affected"))

    def test_names_only_warehouse_is_unchecked(self):
        products = [{"product": "mosquitto", "version": None, "unranged": True}]
        self.assertEqual(queries.component_match(products, [("mosquitto", "2.0.18")])[1], "unchecked")



class PlainTitlesTest(unittest.TestCase):
    def test_summary_is_the_first_real_sentence(self):
        self.assertEqual(queries.summary("In Mosquitto before 1.4.12, ACLs can be bypassed. More text here."),
                         "In Mosquitto before 1.4.12, ACLs can be bypassed")
        self.assertEqual(queries.summary("navigation2 is a ROS 2 Navigation Framework and System. In 1.3.11 and "
                                         "prior, a crafted message crashes the planner."),
                         "In 1.3.11 and prior, a crafted message crashes the planner")

    def test_long_summaries_are_cut_at_a_word(self):
        title = queries.summary("word " * 60)
        self.assertLessEqual(len(title), 97)
        self.assertTrue(title.endswith("…"))

    def test_fixed_version_comes_from_the_range(self):
        products = PRODUCTS["CVE-2017-7650"]
        self.assertEqual(queries.fixed_version(products, "mosquitto", "1.4.10"), "1.4.12")
        self.assertIsNone(queries.fixed_version(products, "openssl", "3.0.2"))

    def test_cve_rows_carry_title_and_fix(self):
        rows = exposure({"mqtt"}, [("mosquitto", "1.4.10")])
        row = rows["CVE-2017-7650"]
        self.assertEqual(row["summary"], "In Mosquitto before 1.4.12")
        self.assertEqual((row["component"], row["fixed_in"]), ("mosquitto", "1.4.12"))

if __name__ == "__main__":
    unittest.main()
