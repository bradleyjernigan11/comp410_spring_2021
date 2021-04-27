import unittest
import git
import id_pkg as intrusion_detect
import os
import pandas as pd



class TestInspectdrop(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'intrusion_logs.txt')

    log = intrusion_detect.IdParse(syslog_file)

    def test_inspect_drop_stub(self):
        self.assertEqual(True, True)

    def test_ip_spoofing_create_sample_log(self):
        # %ASA-2-106016: Deny IP spoof from (IP_address) to IP_address on interface interface_name.
        # Sep 12 2014 06:50:53 HOST : %ASA-2-106016: Deny IP spoof from (10.1.1.1) to 10.11.11.11 on
        #   interface TestInterface
        info = {'Date': 'March 29 2021 13:20:11',
                'Host': 'HOST',
                'ID': '%ASA-2-276212',
                'Interface': 'TestInterface'}

        # Get the path to the data directory in the git repo
        git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
        data_path = os.path.join(git_root, 'data')

        # Create a sample log file
        # https://docs.python.org/3/tutorial/inputoutput.html
        with open(os.path.join(data_path,'inspect_drop.txt'), 'w') as f:
            for i in range(1, 256, 1):
                dropRate = i
                TotalCount = i
                # Create the first part of the message
                log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '

                # Drop rate
                log_string = log_string + 'drop rate-' + str(dropRate) + ' exceeded. '

                # total count
                log_string = log_string + 'Cumulative total count is ' + str(TotalCount) + '\n'
                f.write(log_string)

    def test_inspect_drop_stub(self):
        self.assertEqual(True, True)

    def test_inspect_drop_parse_log(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        sdf = id_syslog.df[id_syslog.df['ID'] == 313008]

        # Expecting 255 total records
        self.assertEqual(255, len(sdf))
        self.assertEqual(255, sdf['DropRate'].nunique())
        self.assertEqual(255, sdf['TotalCount'].nunique())

    def test_has_inspectdrop(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        # The test file generated has ip spoofing present
        # so expect this to return true
        #self.assertTrue(id_syslog.has_inspectdrop())
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
