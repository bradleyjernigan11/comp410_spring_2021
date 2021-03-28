import unittest
import os
import git
import random


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
            denial_of_service = denial_of_service + ' to ' + '10.' + ip_address_2 +'.'+ ip_address_3 + '.'+ip_address_4 + '\n'
            f.write(denial_of_service)

    def test_denial_of_service_stub(self):
        self.assertEqual(True, True)




if __name__ == '__main__':
    unittest.main()
