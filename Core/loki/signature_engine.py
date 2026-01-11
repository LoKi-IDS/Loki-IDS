# Signature detection engine
# 
# NOTE: This is the YAML-based engine (legacy/standalone mode).
# 
# When using database integration (recommended):
#   - Use: Web-Interface/run_ids_with_integration.py
#   - That script uses: Web-Interface/integration/db_signature_engine.py (database-backed)
#   - This file is NOT used when running with integration
#
# This file is kept for:
#   - Standalone YAML-only mode (no database)
#   - Backward compatibility
#   - Direct execution of Core/loki/nfqueue_app.py
#
import yaml
import os


class SignatureScanning:
    """
    YAML-based signature engine (legacy/standalone mode).
    
    This class loads signatures from YAML file.
    
    For database-backed signatures (recommended):
        Use Web-Interface/run_ids_with_integration.py
        which uses integration/db_signature_engine.py instead.
    
    This class is kept for:
        - Standalone operation (no database)
        - Backward compatibility
        - Direct execution of nfqueue_app.py
    """
    def __init__(self, yaml_file_path="../../Configs/test_yaml_file.yaml"):
        # the dict will be : RULE_ID -> (description, data, action, rule id)
        self.rule = {"TEST_RULE" : ("test malicious rule", b"ATTACK_TEST", True, "ID1 TEST_RULE")} # just for testing..
        self.rules = []
        self.yaml_file_path = yaml_file_path
        self.load_rules(yaml_file_path)

    def load_rules(self, file_path=None):
        """
        Load rules from YAML file.
        If file_path is None, uses the instance's yaml_file_path.
        """
        if file_path is None:
            file_path = self.yaml_file_path
        
        # Resolve relative path
        if not os.path.isabs(file_path):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(current_dir, file_path)
        
        try:
            with open(file_path, 'r') as f:
                all_rules = yaml.safe_load(f)
                #print("opening the file path is done.")

            # Clear existing rules
            self.rules = []
            
            # now we have all the rules organized as a dictionaries..
            # let's add them to the rules variable
            
            for block in all_rules.get('signatures', []):
               # print(f"current block is : {block}")
                block['pattern_bytes'] = block['pattern'].encode('utf-8')
                self.rules.append(block)

            print(f"[*] loading of the rules from {file_path} is done.")
            print(f"[*] number of rules loaded is {len(self.rules)}.")
           # print(f"the rules are : \n{self.rules}")
           # print("================***==============")

        except Exception as e:
            print(f"[!]ERROR while loading the yaml file: {e}")
    
    def reload_rules(self):
        """
        Reload rules from the YAML file.
        Useful when signatures are updated via web interface.
        """
        print("[*] Reloading signatures from YAML file...")
        self.load_rules()
        print(f"[*] Reloaded {len(self.rules)} signatures")
        return len(self.rules)

    def CheckPacketPayload(self, payload):
        # we should get the payload itself like pkt[Raw].load
        # it won't matter if it's tcp or udp
        Rule = self.rule.get("TEST_RULE")
        try:
            for rule in self.rules:
                if rule.get('pattern_bytes') in payload:
                    return rule.get('name'), rule.get('pattern'), rule.get('action')
                    # note that if the packet matches many ruless, then now this code will return
                    # only the first rule that matches, keep in mind that we need to modify it.
            
        except Exception as e:
            print(f"[-] ERROR while checking the packet : {e}")
            
        return 0,0,0
