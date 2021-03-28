import unittest
import os
import git
import random
import id_pkg as detection


#%ASA-2-106017: Deny IP due to Land Attack from IP_address to IP_address
class TestDenialofService(unittest.TestCase):
    pkg_path = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    log_file = os.path.join(pkg_path, 'data','denial_of_service.txt')
    info = {
        'Date': 'March 29 2021 10:40:40',
        'Host': 'HOST',
        'ID': '%ASA-2-106017',

    }
    with open(log_file, 'w') as f:
        for ip_address in range(1, 256, 1):
            ip_address_2 = str(random.randint(1, 255))
            ip_address_3 = str(random.randint(1, 255))
            ip_address_4 = str(random.randint(1, 255))
            denial_of_service = info['Date'] + ' ' + info['Host'] + ' : '
            denial_of_service = denial_of_service + info['ID'] + ': '
            denial_of_service = denial_of_service + 'Deny IP due to land attack from ' + '10.'+ip_address_2 + '.'+ip_address_3 + '.'+ ip_address_4
            denial_of_service = denial_of_service + ' to ' + '10.' + ip_address_2 +'.'+ ip_address_3 + '.'+ ip_address_4 + '\n'
            f.write(denial_of_service)

    def test_denial_of_service_stub(self):
        self.assertEqual(True, True)
    def test_denial_of_service_log_parse(self):
        id_pkg_logs = detection.IdParse(self.log_file)
        denial_of_service_log_df = id_pkg_logs.df[id_pkg_logs.df['ID'] == 106017]
        #run tests on the dataframe

        self.assertEqual(255, len(denial_of_service_log_df))
        # source should be identical to destination
        self.assertTrue((denial_of_service_log_df['Source'] == denial_of_service_log_df['Destination']).all)

    def test_has_denial_of_service(self):
        id_pkg_logs = detection.IdParse(self.log_file)
        self.assertEqual(True, id_pkg_logs.has_denial_of_service())





if __name__ == '__main__':
    unittest.main()
