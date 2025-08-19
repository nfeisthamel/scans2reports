"""
This package contains stateless methods that support teh report generator
"""
import logging
import sys
import os.path
import re
import datetime
import copy
import secrets
import pprint
import dumper
import unicodedata
import string
from utils import Utils

from lxml import etree
from PyQt5 import QtCore, QtGui, QtWidgets

class ScanUtils():
    """
    Class that contains static methods that support the report generator
    """
    @staticmethod
    def update_ckl(source, destination, main_app):
        """
        Copy STATUS / COMMENTS / FINDING_DETAILS from source to destination,
        supporting XML (.ckl) and JSON (.cklb) in any combination.
        Matching tries BOTH:
          1) normalized rule_id (strip trailing '_rule')
          2) group/vuln id (V-xxxxx)  [stable across releases]
        """
        import json
        from lxml import etree

        # --- setup / logging (unchanged) -----------------------------------------
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))

        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{application_path}/scans2reports.log", level=logging.INFO, format=FORMAT)
        logging.info('Update CKL')

        status_msg = f"Updating {source} -> {destination}"
        logging.info(status_msg)
        print(status_msg)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(status_msg)
            main_app.main_window.progressBar.setValue(0)
            QtGui.QGuiApplication.processEvents()

        # --- helpers --------------------------------------------------------------
        def _read_text(path):
            with open(path, 'r', errors='replace', encoding='utf-8') as f:
                return f.read()

        def _read_xml_tree(path):
            with open(path, 'r', errors='replace', encoding='utf-8') as f:
                lines = f.readlines()
            start = 0
            if lines and '?' in lines[start]:
                start += 1
            if len(lines) > start and '!' in lines[start]:
                start += 1
            raw = ''.join(lines[start:])
            raw = ''.join([ch if ord(ch) < 128 else ' ' for ch in raw])
            return etree.fromstring(raw.encode('utf-8'))

        def _is_json_cklb(path):
            ext = os.path.splitext(path)[1].lower()
            if ext != '.cklb':
                return False
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    first = f.readline().lstrip()
                return first.startswith('{') or first.startswith('[')
            except:
                return False

        def _norm_rule_id(val: str) -> str:
            """Uppercase and strip trailing '_RULE' so XML/JSON rule IDs align."""
            if not val:
                return ''
            s = str(val).strip().upper()
            if s.endswith('_RULE'):
                s = s[:-5]
            return s

        def _norm_vuln_id(val: str) -> str:
            return (val or '').strip().upper()

        # Build: key -> {'status','comments','finding_details'}
        # Keys include BOTH normalized rule_id and vuln_id for maximum match.
        def _extract_from_source(path):
            data = {}
            if _is_json_cklb(path):
                # JSON source
                try:
                    j = json.loads(_read_text(path))
                except Exception as e:
                    logging.error(f"Failed to read JSON CKLB source: {path}: {e}")
                    return data

                for s in j.get('stigs', []):
                    rules = s.get('vulns') or s.get('rules', [])
                    for r in rules:
                        rid = r.get('rule_id') or r.get('ruleID') or r.get('ruleId') or ''
                        gid = r.get('group_id') or r.get('vulnNum') or r.get('groupId') or ''
                        info = {
                            'status': (r.get('status') or '').strip(),
                            'comments': r.get('comments') or '',
                            'finding_details': r.get('finding_details') or '',
                        }
                        for k in { _norm_rule_id(rid), _norm_vuln_id(gid) } - {''}:
                            data[k] = info
            else:
                # XML source
                try:
                    tree = _read_xml_tree(path)
                except Exception as e:
                    logging.error(f"Failed to read XML CKL source: {path}: {e}")
                    return data

                for v in tree.xpath("//VULN"):
                    rid = next(iter(v.xpath("*[./VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA/text()")), '')
                    gid = next(iter(v.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), '')
                    info = {
                        'status': next(iter(v.xpath("./STATUS/text()")), '') or '',
                        'comments': next(iter(v.xpath("./COMMENTS/text()")), '') or '',
                        'finding_details': next(iter(v.xpath("./FINDING_DETAILS/text()")), '') or '',
                    }
                    for k in { _norm_rule_id(rid), _norm_vuln_id(gid) } - {''}:
                        data[k] = info
            return data

        # Apply to destination; return (updated_obj, total, matched)
        def _apply_to_destination(path, source_map):
            total = 0
            matched = 0

            if _is_json_cklb(path):
                # JSON destination
                try:
                    j = json.loads(_read_text(path))
                except Exception as e:
                    logging.error(f"Failed to read JSON CKLB destination: {path}: {e}")
                    return None, total, matched

                rulesets = j.get('stigs', [])
                total = sum(len(s.get('vulns') or s.get('rules', [])) for s in rulesets)

                done = 0
                for s in rulesets:
                    rules = s.get('vulns') or s.get('rules', [])
                    for r in rules:
                        if main_app.main_window and total:
                            done += 1
                            main_app.main_window.progressBar.setValue(int(done/total*100))
                            QtGui.QGuiApplication.processEvents()

                        rid = r.get('rule_id') or r.get('ruleID') or r.get('ruleId') or ''
                        gid = r.get('group_id') or r.get('vulnNum') or r.get('groupId') or ''
                        candidates = [_norm_rule_id(rid), _norm_vuln_id(gid)]

                        hit = next((k for k in candidates if k and k in source_map), None)
                        if hit:
                            info = source_map[hit]
                            r['status'] = info.get('status', r.get('status', ''))
                            r['comments'] = info.get('comments', r.get('comments', ''))
                            r['finding_details'] = info.get('finding_details', r.get('finding_details', ''))
                            matched += 1

                return j, total, matched

            else:
                # XML destination
                try:
                    tree = _read_xml_tree(path)
                except Exception as e:
                    logging.error(f"Failed to read XML CKL destination: {path}: {e}")
                    return None, total, matched

                vulns = tree.xpath("//VULN")
                total = len(vulns)
                done = 0

                for v in vulns:
                    if main_app.main_window and total:
                        done += 1
                        main_app.main_window.progressBar.setValue(int(done/total*100))
                        QtGui.QGuiApplication.processEvents()

                    rid = next(iter(v.xpath("*[./VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA/text()")), '')
                    gid = next(iter(v.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), '')
                    candidates = [_norm_rule_id(rid), _norm_vuln_id(gid)]

                    hit = next((k for k in candidates if k and k in source_map), None)
                    if hit:
                        info = source_map[hit]
                        for tag in ('STATUS', 'COMMENTS', 'FINDING_DETAILS'):
                            node = v.find(tag)
                            if node is None:
                                node = etree.SubElement(v, tag)
                            node.text = info.get(tag.lower(), node.text or '')
                        matched += 1

                return tree, total, matched

        # --- run -----------------------------------------------------------------
        src_map = _extract_from_source(source)
        updated_dest, total_items, matched_items = _apply_to_destination(destination, src_map)

        if updated_dest is None:
            msg = "Update failed: could not parse destination."
            logging.error(msg)
            print(msg)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(msg)
                main_app.main_window.progressBar.setValue(0)
                QtGui.QGuiApplication.processEvents()
            return

        # Build output path in results/, keep destination extension
        results_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'results')
        os.makedirs(results_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(destination))[0]
        ext = os.path.splitext(destination)[1]
        stamp = (datetime.datetime.now()).strftime('%Y%m%d_%H%M%S')
        out_path = os.path.join(results_dir, f"{base}_updated_{stamp}{ext}")

        # Write back
        if _is_json_cklb(destination):
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(updated_dest, f, ensure_ascii=False, indent=2)
        else:
            with open(out_path, 'wb') as f:
                f.write(etree.tostring(updated_dest))

        print(f"Updated checklist saved to {out_path} ({matched_items}/{total_items} items updated)")
        done_msg = "Finished Updating CKL"
        logging.info(done_msg)
        print(done_msg)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(done_msg)
            main_app.main_window.progressBar.setValue(0)
            QtGui.QGuiApplication.processEvents()


    def split_nessus_file(file, main_app):
        with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
            content = content_file.readlines()
        content = ''.join(content)
        tree = etree.fromstring( str(content ) )

        report_hosts = tree.xpath("/NessusClientData_v2/Report/ReportHost")
        total_hosts = len(report_hosts)
        index = 0

        for host in report_hosts:
            index += 1
            fqdn_val = Utils.fqdn(host)

            scan_date = datetime.datetime.strptime(
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), ''))
                , '%a %b %d %H:%M:%S %Y'
            ).strftime("%Y%m%d_%H%M%S")

            status = f"Processing host: {fqdn_val}, scan date: {scan_date}"
            logging.info(status)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*index/total_hosts*.9)   )
                QtGui.QGuiApplication.processEvents()

            report_name = "{}/results/{}_{}.nessus".format(
                os.path.dirname(os.path.realpath(__file__)),
                fqdn_val,
                scan_date
            )

            host_nessus = copy.deepcopy(tree)
            for host in host_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                host_fqdn_val = Utils.fqdn(host)

                if host_fqdn_val != fqdn_val:
                    host.getparent().remove(host)

            report_task_id = "{}-{}-{}-{}-{}-{}".format(
                secrets.token_hex(4),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(14)
            )
            report_node = host_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
            if report_node:
                report_node[0].text = report_task_id

            host_tree = host_nessus.getroottree()
            host_tree.write(report_name)

        status = f"Split Nessus File is in results folder"
        logging.info(status)
        print(status)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage("Ready")
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents()

    def merge_nessus_files(files, host_count, main_app):
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        if not isinstance(host_count, int) or host_count <= 0:
            status = "Error: host_count must be a positive integer greater than zero."
            Utils.update_status(application_path, main_app, status, 0)
            logging.error(status)
            print(status)
            return

        policies = {}
        
        status = "Merging selected Nessus Files"
        Utils.update_status(application_path, main_app, status, 0 )
        logging.info(status)
        print(status)
        
        total_files = len(files)
        current_file = 0
        for file in files:
            
            current_file += 1
        
            status = "Processing file {}".format(file)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
        
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*current_file/total_files*.5)   )
                QtGui.QGuiApplication.processEvents()
                
            with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.read()
                # Strip .nessus encoding if found
                if content.startswith('<?xml'):
                    content = content[content.find('?>') + 2:].lstrip()
                tree = etree.fromstring(content.encode('utf-8'))
                # content = content_file.readlines()
            # content = ''.join(content)
            # tree = etree.fromstring( str(content ) )

            #get the current files policy name and policy definition            
            version_check = tree.xpath("/NessusClientData_v2/Policy/policyName/text()")
            if version_check:
                policy_name = str(next(iter( tree.xpath("/NessusClientData_v2/Policy/policyName/text()")), "" ) )
            else:
                policy_name = str(next(iter( tree.xpath("/NessusClientData_v2/Policy/PolicyName/text()")), "" ) )
            policy_def = copy.deepcopy( tree.xpath("/NessusClientData_v2/Policy") )
            
            status = "    Policy {} Discovered".format(policy_name)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
            
            #if first time policy has been processed, add it to the policies list (with no hosts)
            if policy_name not in policies.keys():
                policies[policy_name] = {}
                policies[policy_name]['policy'] = policy_def[0]
                policies[policy_name]['hosts'] = []

            #now...add all found hosts in the current file to applicable policy item
            for host in tree.xpath("/NessusClientData_v2/Report/ReportHost"):
                clone_host = copy.deepcopy(host)
                policies[policy_name]['hosts'].append(clone_host)
        
        status = "Generating result scans based off of policies"
        Utils.update_status(application_path, main_app, status, 0 )
        logging.info(status)
        print(status)
        total_policies = len(policies.keys())
        current_policy = 0
        for policy in policies.keys():
            current_policy += 1
        
            status = "    Processing Policy {}".format(policy)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*current_policy/total_policies*.5)+50   )
                QtGui.QGuiApplication.processEvents()
                
            chunk_index = 0
            final = [policies[policy]['hosts'][i * host_count:(i + 1) * host_count] for i in range((len(policies[policy]['hosts']) + host_count - 1) // host_count )]  
            for chunk in final:
                chunk_index += 1
                
                status = "        Processing Chunk {}".format(chunk_index)
                Utils.update_status(application_path, main_app, status, 0 )
                logging.info(status)
                print(status)
                
                root = etree.Element("NessusClientData_v2")
                root.append( policies[policy]['policy'] )
                report_node = etree.Element("Report") 
                root.append( report_node  )
                
                for host in chunk:
                    report_node.append( host )
                    
                safe_policy_name = str(policy)
                safe_policy_name = re.sub('[^\w_.)( -]', '', safe_policy_name)
                report_name = "{}/results/merged_POLICY-{}_CHUNK-{}.nessus".format( 
                    os.path.dirname(os.path.realpath(__file__)), 
                    safe_policy_name,
                    str(chunk_index).zfill(3)
                )
                    
                report_task_id = "{}-{}-{}-{}-{}-{}".format( secrets.token_hex(4), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(14) )
                report_node = root.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
                if report_node:
                    report_node[0].text = report_task_id
                
                targets = []
                for current_host in root.xpath("/NessusClientData_v2/Report/ReportHost"):
                     targets.append(next(iter(current_host.xpath("./@name")),''))
                targets = sorted(list(set(targets)))
                target_node = root.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'TARGET']/value")
                if target_node:
                    target_node[0].text = ",".join(targets)
                
                my_tree = etree.ElementTree(root)
                with open(report_name, 'wb') as f:
                    f.write(etree.tostring(my_tree))
    
        status = "Merged Nessus File(s) are in results folder"
        Utils.update_status(application_path, main_app, status, 0 )
        print(status)

    @staticmethod
    def clean_ip(ip_raw):
        """Strip CIDR notation from IP address"""
        if not ip_raw:
            return ''
        return ip_raw.strip().split('/')[0]

    @staticmethod
    def clean_mac(mac_raw):
        """Sanitize and format a MAC address to colon-separated format"""
        if not mac_raw:
            return ''
        hex_str = re.sub(r'[^0-9a-fA-F]', '', mac_raw)
        if len(hex_str) < 12:
            return ''
        return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2)).upper()