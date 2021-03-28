import unittest
import os
import git
import id_pkg as detection


class FireWallTest(unittest.TestCase):
    git_root = os.path.join(git.Repo(".", search_parent_directories=True).working_tree_dir, 'id_pkg')
    log_file = os.path.join(git_root, 'data', "firewall_log.txt")

    # %ASA-3-713163: Remote user (session Id - id) has been terminated by the Firewall Server

    info = {
        'Date': 'March 16 2021 10:40:40',
        'Host': 'HOST',
        'ID': '%ASA-3-713163',
        'SessionID': 'kdsnfegnkngerubop3r843yth82gjnf'
    }

    # implementing mock log file for firewall
    with open(log_file, 'w') as f:
        for session_id in range(1, 256, 1):
            firewall_log_data = info['Date'] + ' ' + info['Host'] + ' : '
            firewall_log_data = firewall_log_data + info['ID'] + ': '
            firewall_log_data = firewall_log_data + 'Remote user (' + info['SessionID'] + ' - '
            firewall_log_data = firewall_log_data + str(session_id) + ') has been terminated by the Firewall Server \n'
            f.write(firewall_log_data)

    def test_firewall_terminate_stub(self):
        self.assertEqual(True, True)

    def test_firewall_log_parse(self):
        id_pkg_logs = detection.IdParse(self.log_file)
        firewall_log_dataframe = id_pkg_logs.df[id_pkg_logs.df['ID'] == 713163]
        # run tests on the dataframe

        self.assertEqual(255, len(firewall_log_dataframe))
        self.assertTrue((firewall_log_dataframe['Session'] == 'kdsnfegnkngerubop3r843yth82gjnf').all())

    def test_has_firewall(self):
        id_pkg_logs = detection.IdParse(self.log_file)
        self.assertEqual(True, id_pkg_logs.has_firewall())
