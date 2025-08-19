import os
import sys
import re
import time
import uuid
import pprint
import logging
import string
import numpy as np
import pandas as pd
import xlrd
import json

from scar_pickles import SCARPickles

from lxml import etree
from scan_file import ScanFile
from scan_requirement import ScanRequirement
from utils import Utils
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets
from scan_utils import ScanUtils
from html import unescape

#TODO Make faster
class ScanParser:
    
    def __init__(self, main_app):
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        self.main_app = main_app

        self.scar_conf = SCARPickles.loader( os.path.join(application_path, "data", "scar_configs.pkl") )
        self.scar_data = SCARPickles.loader( os.path.join(application_path, "data", "scar_data.pkl") )

        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{self.scar_conf.get('application_path')}/scans2reports.log", level=logging.INFO, format=FORMAT)

    def parseCsv(self, filename):
        df = pd.read_csv(filename, quotechar='"', skipinitialspace=True, encoding='utf-8', dtype=str)

        if 'Mitigation' in df.keys() and 'Finding ID' in df.keys():
            data_type = 'Mitigations'
            field_name = 'Mitigation'
            list_name = 'mitigations'
            value_key = 'mitigation'
        elif 'Impact Description' in df.keys() and 'Finding ID' in df.keys():
            data_type = 'ImpactDescriptions'
            field_name = 'Impact Description'
            list_name = 'impacts'
            value_key = 'impact'
        elif 'Resources Required' in df.keys() and 'Finding ID' in df.keys():
            data_type = 'ResourcesRequired'
            field_name = 'Resources Required'
            list_name = 'resources'
            value_key = 'resource'
        else:
            logging.warning(f"Unrecognized CSV structure in {filename}. Missing expected columns.")
            return None

        results = {'type': data_type, list_name: []}

        for index, row in df.iterrows():
            source = row['Finding ID'].strip()

            plugin_pattern = r'^([0-9]{3,6})$'
            plugin_match = re.search(plugin_pattern, source, re.IGNORECASE)
            plugin_id = plugin_match.group(1).strip() if plugin_match else ''

            rule_pattern = r'^(SV-[0-9.]+r[0-9]+_rule)$'
            rule_match = re.search(rule_pattern, source, re.IGNORECASE)
            rule_id = rule_match.group(1).strip() if rule_match else ''

            vuln_pattern1 = r"\W(V-[0-9]+)"
            vuln_match = re.search(vuln_pattern1, source.upper())
            if vuln_match:
                vuln_id = vuln_match.group(1).strip()
            else:
                vuln_pattern2 = r"^(V-[0-9]+)"
                vuln_match = re.search(vuln_pattern2, source.upper())
                vuln_id = vuln_match.group(1).strip() if vuln_match else ''

            raw_value = row.get(field_name, '')
            value = str(raw_value).strip() if pd.notna(raw_value) else ''

            results[list_name].append({
                'plugin_id': plugin_id,
                'rule_id': rule_id,
                'vuln_id': vuln_id,
                'control': '',
                value_key: value,
                'source': source
            })

        logging.info(f"Finished processing {data_type} CSV. Total entries: {len(results[list_name])}")
        return results       
    
    def parseExcel(self, filename):

        #df is the data format read.  used to determine the type of excel file being read prior to looping the rows.
        df = pd.read_excel(filename, None);
        safe_keys = ( [ ( "".join([ch for ch in i.upper() if ch in (string.ascii_letters + string.digits)]) )   for i in df.keys()  ] )
        
        if 'POAM' in safe_keys:
            poam_rows = None
            for key in df.keys():
                if ( "".join([ch for ch in key.upper() if ch in (string.ascii_letters + string.digits)]) ) == 'POAM':
                    poam_rows = pd.read_excel(filename, key, header=0, index_col=None, na_values=['NA'], mangle_dupe_cols=True)
            
            if poam_rows is not None and not poam_rows.empty:
                poam_results = {}
                poam_results['type'] = 'Mitigations'
                poam_results['mitigations'] = []
                
                for poam in poam_rows.index:
                
                    source = str(poam_rows['Security Checks'][poam]).strip()
                    
                    plugin_id = re.search('^([0-9]{3,6})$', source.strip())
                    plugin_id = plugin_id.group(1).strip() if plugin_id is not None else ''
                
                    rule_id = re.search('(SV-[0-9.]+r[0-9]+_rule)', source.strip())
                    rule_id = rule_id.group(1).strip() if rule_id is not None else ''
                
                    vuln_id = re.search("\W(V-[0-9]+)", source.upper())
                    vuln_id = vuln_id.group(1).strip() if vuln_id is not None else ''
                    
                    if vuln_id == '':
                        vuln_id = re.search("^(V-[0-9]+)", source.upper())
                        vuln_id = vuln_id.group(1).strip() if vuln_id is not None else ''
                    
                    control = poam_rows['Security Control Number (NC/NA controls only)'][poam]
                    
                    mitigation = poam_rows['Mitigations'][poam]
                    
                    poam_results['mitigations'].append({
                        'plugin_id': plugin_id,
                        'rule_id': rule_id,
                        'vuln_id': vuln_id,
                        'control': control,
                        'mitigation': mitigation,
                        'source': source
                    })
                
                return poam_results
            
        if 'Test Result Import' in df.keys():
            tr_rows = pd.read_excel(filename, 'Test Result Import', header=5, index_col=None, na_values=['NA'], mangle_dupe_cols=True)
            
            test_results_data = {}
            test_results_data['type'] = 'Test Results'
            for tr in tr_rows.index:
                test_results_data[ str( tr_rows['CCI'][tr]).strip().replace('CCI-','').zfill(6) ] = {
                    'control'           : tr_rows['Control Acronym'][tr],
                    'implementation'    : tr_rows['Control Implementation Status'][tr],
                    'ap'                : tr_rows['AP Acronym'][tr],
                    'cci'               : tr_rows['CCI'][tr],
                    'inherited'        : tr_rows['Inherited'][tr],
                    
                    'compliance_status' : tr_rows['Compliance Status.1'][tr],
                    'date_tested'       : tr_rows['Date Tested.1'][tr],
                    'tested_by'         : tr_rows['Tested By.1'][tr],
                    'test_results'      : tr_rows['Test Results.1'][tr]
                }
                
            return test_results_data
            
    def extract_dynamic_plugin_ids(self, nessus_path, output_json_path):
        """Extracts plugin IDs from a .nessus file that contain port/service mappings (port != 0)"""
        import xml.etree.ElementTree as ET
        import json
        
        with open(nessus_path, 'r', encoding='utf-8', errors='replace') as f:
            xml_content = f.read()
            
        root = ET.fromstring(xml_content)
        plugin_ids = set()
        
        for report_host in root.findall(".//ReportHost"):
            for report_item in report_host.findall("ReportItem"):
                plugin_id = report_item.get("pluginID")
                port = report_item.get("port", "0")
                svc_name = report_item.get("svc_name", "")
                
                if plugin_id and svc_name and port.isdigit() and port != "0":
                    plugin_ids.add(int(plugin_id))
                    
        with open(output_json_path, "w") as f:
            json.dump(sorted(plugin_ids), f, indent=2)
            
        return plugin_ids
    
    def inject_dynamic_plugins_into_scar_data(self):
        """Merges dynamic plugin IDs into scar_data.pkl (in memory and on disk)."""
        dynamic_path = os.path.join("data", "dynamic_plugins.json")
        if not os.path.isfile(dynamic_path):
            logging.info("No dynamic_plugins.json found.")
            return
            
        with open(dynamic_path, "r") as f:
            dynamic_plugins = json.load(f)
            
        # inject into existing list
        acas_plugins = self.scar_data.get("data_mapping", {}).get("acas_required_info", [])
        merged = sorted(set(acas_plugins + dynamic_plugins))
        
        if "data_mapping" in self.scar_data:
            self.scar_data["data_mapping"]["acas_required_info"] = merged
            self.scar_data.set("data_mapping", self.scar_data["data_mapping"])
            logging.info("Updated scar_data.pkl with dynamic plugins.")
    
    def parseNessus(self, filename):
        # logging.debug(f"Keys in scar_data: {list(self.scar_data.keys())}")
        logging.info('Parsing ACAS File %s', filename)
        
        # load dynamic-plugin list for this run
        dyn_json = os.path.join(self.scar_conf.get("application_path"),
            "data",
            "dynamic_plugins.json")
        self.extract_dynamic_plugin_ids(filename, dyn_json)
        
        # inject the dynamic plugins into scar_data (in-memory and on-disk .pkl)
        self.inject_dynamic_plugins_into_scar_data()
        
        sf = None
        try:
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.read()
            
            # Strip .nessus encoding if found
            if content.startswith('<?xml'):
                content = content[content.find('?>') + 2:].lstrip()
            tree = etree.fromstring(content.encode('utf-8'))

            version = re.search(
                'Nessus version : ([0-9.]+)',
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/ReportItem[@pluginID='19506']/plugin_output/text()")), ''))
            )
            version =  version.group(1) if version is not None else ''

            feed = re.search(
                'Plugin feed version : ([0-9.]+)',
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/ReportItem[@pluginID='19506']/plugin_output/text()")), ''))
            )
            feed =  feed.group(1) if feed is not None else ''
            
            sf = ScanFile({
                'type'         :'ACAS',
                'filename'     : str(filename),
                'scan_date'     : str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), '')),
                'title'        : "Assured Compliance Assessment Solution (ACAS) Nessus Scanner\nVersion: {}\nFeed: {}".format(version, feed),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'policy'       : str(next(iter(tree.xpath("/NessusClientData_v2/Policy/policyName/text()")), '')) + str(next(iter(tree.xpath("/NessusClientData_v2/Policy/PolicyName/text()")), '')),
                'hostname'     : '',
                'os'           : '',
                'ip'           : '',
                'hosts'        : [],
                'feed'         : feed,
            })
            
            #Debugging
            # try:
                # logging.debug(f"type(self.scar_data): {type(self.scar_data)}")
                # logging.debug(f"dir(self.scar_data): {dir(self.scar_data)}")
                # logging.debug(f"self.scar_data.get: {self.scar_data.get}")
            # except Exception as e:
                # logging.exception("Exception inspecting self.scar_data")

            # try:
                # acas_mapping = self.scar_data.get("acas_control", {})
                # logging.debug(f"type(acas_mapping): {type(acas_mapping)}")
                # logging.debug(f"acas_mapping.get: {acas_mapping.get}")
                # logging.debug(f"dir(acas_mapping): {dir(acas_mapping)}")
                # logging.debug(f"Loaded ACAS Control Mapping: {list(acas_mapping.keys())}")
            # except Exception as e:
                # logging.exception("Exception accessing acas_mapping")
                
            #acas_mapping = self.scar_data.get("acas_control", {})
            acas_mapping = self.scar_data.get("data_mapping", {}).get("acas_control", {})
            #logging.debug(f"Loaded ACAS Control Mapping: {list(acas_mapping.keys())[:10]}")
            #logging.debug(f"Loaded ACAS Control Mapping: {list(acas_mapping.keys())}")

            
            for host in tree.xpath("/NessusClientData_v2/Report/ReportHost"):
                netstat_entries = []
                scan_user = ""
                port_range = ""
                duration = ""
                scan_info = str( host.xpath("./ReportItem[@pluginID=19506]/plugin_output/text()") ).split("\\n")
                for line in scan_info:
                    if 'Credentialed checks' in line:
                        k,v = line.split(':', 1)
                        try:
                            if str(v).strip() == 'no':
                                scan_user = 'NONE'
                            elif len( v.split(' as ') ) > 0:
                                scan_user = str(v.split(' as ')[1]).strip().replace('\\\\','\\')
                            else:
                                scan_user = str(v)
                        except:
                            scan_user = 'UNKNOWN'
                            
                    if 'Port range' in line:
                        k,v = line.split(':', 1)
                        port_range = str(v).strip()
                        
                    if 'scan duration' in line.lower():
                        k,v = line.split(':', 1)
                        duration = str(v).strip()
                
                wmi_info = str( host.xpath("./ReportItem[@pluginID=24270]/plugin_output/text()") ).split("\\n")
                device_type = ""
                manufacturer = ""
                model = ""
                serial = ""
                for line in wmi_info:
                    if ':' in line:
                        k,v = line.split(':', 1)
                        try:
                            if str(k).strip() == 'Computer Manufacturer':
                                manufacturer = str(v).strip()
                            elif str(k).strip() == 'Computer Model':
                                model = str(v).strip()
                            elif str(k).strip() == 'Computer SerialNumber':
                                serial = str(v).strip()
                            elif str(k).strip() == 'Computer Type':
                                device_type = str(v).strip()
                        except:
                            device_type = ""
                            manufacturer = ""
                            model = ""
                            serial = ""
                
                fqdn_val = Utils.fqdn(host)
                
                host_data = {
                    'hostname'      : fqdn_val,
                    'ip'            : next(iter(host.xpath("./HostProperties/tag[@name='host-ip']/text()")),''),
                    'mac'           : next(iter(host.xpath("./HostProperties/tag[@name='mac-address']/text()")),''),
                    'os'            : next(iter(host.xpath("./HostProperties/tag[@name='operating-system']/text()")),''),
                    
                    'device_type'   : device_type,
                    'manufacturer'  : manufacturer,
                    'model'         : model,
                    'serial'        : serial,
                    
                    'host_date'     : str(next(iter(host.xpath("./HostProperties/tag[@name='HOST_START']/text()")), '')),
                    'credentialed'  : Utils.parse_bool(str(next(iter( host.xpath("./HostProperties/tag[@name='Credentialed_Scan']/text()")), ''))),
                    'scan_user'     : scan_user,
                    'port_range'    : port_range,
                    'duration'      : duration,
                    'requirements'  : []
                }
                
                # Extract Netstat connection info
                
                for tag in host.xpath("./HostProperties/tag"):
                    name = tag.get("name", "")
                    value = tag.text or ""
                    
                    if name.startswith("netstat-established-"):
                        # Extract protocol and address from tag name and value
                        parts = name.split("-")
                        if len(parts) < 3:
                           continue
                           
                        proto_raw = parts[2]
                        if proto_raw.startswith("tcp"):
                            proto = "tcp"
                        elif proto_raw.startswith("udp"):
                            proto = "udp"
                        else:
                            proto = "unknown"
                        
                        try:
                            if "-" not in value:
                                continue
                            left, right     = value.split("-", 1)
                            orig_ip, o_port = left.rsplit(":", 1)
                            dest_ip, d_port = right.rsplit(":", 1)
                            
                            if (
                                any(ip.startswith(("0.0.0.0", "127.")) or ":" in ip or "[" in ip
                                    for ip in (orig_ip, dest_ip))
                            ):
                                continue
                            
                            netstat_entries.append({
                                "proto"       : proto,
                                "origin_ip"   : orig_ip,
                                "origin_port" : int(o_port),
                                "dest_ip"     : dest_ip,
                                "dest_port"   : int(d_port),
                            })
                            
                        except ValueError:
                            continue
                            
                host_data["netstat"] = netstat_entries

                for req_node in host.xpath("./ReportItem"):
                    if self.main_app.main_window:
                        QtGui.QGuiApplication.processEvents()
                    
                    severity = int(next(iter(req_node.xpath("./@severity")),''))
                    plugin_id = int(next(iter(req_node.xpath("./@pluginID")),''))
                    
                    if not self.scar_conf.get('skip_info') or ( severity != 0 or plugin_id in self.scar_data.get('data_mapping')['acas_required_info'] ):
                    
                        iavms = []
                        for iava in req_node.xpath("./iava"):
                            if str(iava.text).strip() != '':
                                iavms.append(iava.text)
                            
                        for iavb in req_node.xpath("./iavb"):
                            if str(iavb.text).strip() != '':
                                iavms.append(iavb.text)
                        
                        for iavt in req_node.xpath("./iavt"):
                            if str(iavt.text).strip() != '':
                                iavms.append(iavt.text)
                        
                        stig_severity = next(iter(req_node.xpath("./stig_severity/text()")),'')
                        
                        #if there is a stig verity, the DoD Risk follows it
                        if stig_severity.strip() != '':
                            severity = int(
                                Utils.risk_val(
                                    str(stig_severity),
                                    'NUM'
                                )
                            )
                            
                        requirement = {
                            'cci'               : 'CCI-000366',
                            'comments'          : next(iter(req_node.xpath("./plugin_output/text()")),''),
                            'description'       : next(iter(req_node.xpath("./synopsis/text()")),'') + "\n\n" + next(iter(req_node.xpath("./description/text()")),''),
                            'finding_details'   : '',
                            'fix_id'            : '',
                            'mitigation'        : '',
                            'port'              : int(next(iter(req_node.xpath("./@port")),'')),
                            'protocol'          : next(iter(req_node.xpath("./@protocol")),''),
                            'service'           : next(iter(req_node.xpath("./@svc_name")),''),
                            'grp_id'            : next(iter(req_node.xpath("./@pluginFamily")),''),
                            'iavm'              : ', '.join(iavms).strip(),
                            'plugin_id'         : plugin_id,
                            'resources'         : '',
                            'rule_id'           : '',
                            'solution'          : next(iter(req_node.xpath("./solution/text()")),''),
                            'references'        : '',
                            'severity'          : severity,
                            'req_title'         : next(iter(req_node.xpath("./@pluginName")),''),
                            'grp_id'            : next(iter(req_node.xpath("./@pluginFamily")),'').strip(),
                            'vuln_id'           : '',
                            'ia_controls'       : [],
                            'status'            : 'O',
                            'publication_date'  : next(iter(req_node.xpath("./plugin_publication_date/text()")),''),
                            'modification_date' : next(iter(req_node.xpath("./plugin_modification_date/text()")),''),
                        }
                        
                        plugin_family = requirement.get('grp_id', '').strip()
                        # acas_mapping_normalized = {k.strip().lower(): v for k, v in acas_mapping.items()}
                        
                        # Debugging
                        # logging.debug(f"type(requirement): {type(requirement)}")
                        # logging.debug(f"requirement.get: {requirement.get}")
                        # logging.debug(f"requirement.get('grp_id'): {requirement.get('grp_id')}")
                        # logging.debug(f"[Nessus Parser] Plugin Family: '{plugin_family}' to Mapped Control: '{acas_mapping.get(plugin_family)}'")
                        # logging.debug(f"[Nessus Parser] Known Mapping Keys: {list(acas_mapping.keys())[:10]}...")  # Show a few mapping keys
                        # logging.debug(f"Plugin family raw: '{requirement.get('grp_id')}'")
                        
                        mapped_control = acas_mapping.get(plugin_family, '')
                        if plugin_family not in acas_mapping:
                            logging.warning(f"Plugin family '{plugin_family}' not found in acas_mapping!")
                            
                        # logging.debug(f"[Nessus Parser] Plugin Family: '{plugin_family}' to Mapped Control: '{mapped_control}'")

                        if mapped_control:
                            requirement['rmf_controls'] = [mapped_control]
                        
                        # Try to find a matching CCI for the RMF control
                        ap_mapping = self.scar_data.get("data_mapping", {}).get("ap_mapping", {})
                        matched_cci = ''
                        
                        for cci, control in ap_mapping.items():
                            if control.startswith(mapped_control):  # loose match: e.g., "CM-6.5" starts with "CM-6"
                                matched_cci = cci
                                break
                        
                        if matched_cci:
                            requirement['cci'] = matched_cci
                        else:
                            requirement['cci'] = 'CCI-000366'  # fallback

                        # debugging
                        # logging.debug(f"[CCI Mapper] RMF: {mapped_control} CCI: {requirement['cci']}")

                        host_data['requirements'].append(requirement)
                # De-duplication logic by hostname
                existing = next((h for h in sf['hosts'] if h['hostname'] == fqdn_val), None)
                if existing:
                    logging.info(f"Duplicate host entry for {fqdn_val} found, merging data.")

                    # Prefer data that's missing in the existing entry
                    for key in ['ip', 'mac', 'os', 'device_type', 'manufacturer', 'model', 'serial']:
                        if not existing.get(key) and host_data.get(key):
                            existing[key] = host_data[key]

                    # Append unique requirements
                    existing_plugin_ids = set(r['plugin_id'] for r in existing['requirements'])
                    for req in host_data['requirements']:
                        if req['plugin_id'] not in existing_plugin_ids:
                            existing['requirements'].append(req)

                    continue  # Don't append a duplicate host
                sf['hosts'].append( host_data )

        except Exception as e:
            sf = None
            logging.error('Error parsing scap file %s', filename)
            logging.error(str(e))
            print(filename)
            print(str(e))

        return sf
        
    def parseScap(self, filename):
        logging.info('Parsing scap file %s', filename)
        sf = None
        try:
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            content = content[2:]
            content = ''.join(content)
            content = ''.join([i if ord(i) < 128 else ' ' for i in content])

            tree = etree.fromstring( str(content ) )
            ns = tree.nsmap

            version = re.search(
                '([0-9]+)\.[0-9]+',
                str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])
            )
            version =  version.group(1) if version is not None else str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])

            if version.isdigit():
                version = str(int(version))
                
            release = re.search(
                '[0-9]+\.([0-9]+)',
                str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])
            )
            release =  release.group(1) if release is not None else str(next(iter(tree.xpath("/cdf:Benchmark/cdf:plain-text/text()", namespaces = ns)), '').split(',')[0])
            if ':' in release:
                release = re.search('Release: [0-9]+\.([0-9]+) Benchmark', release)
                release = release.group(1) if release is not None else '0'

            if release.isdigit():
                release = str(int(release))

            fqdn_val = ""
            if next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:fqdn']/text()", namespaces = ns)), ''):
                fqdn_val = str( next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:fqdn']/text()", namespaces = ns)), '') ).lower()
            elif next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target/text()", namespaces = ns)), ''):
                fqdn_val =  str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target/text()", namespaces = ns)), '')).lower()
            elif next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), ''):
                fqdn_val = str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), '')).lower()
            else:
                fqdn_val = 'UNKNOWN'
            
            sf = ScanFile({
                'type'         :'SCAP',
                'filename'     : str(filename),
                'scan_date'     : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@start-time", namespaces = ns )), ''),
                'duration'     :
                    datetime.strptime(
                        str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@end-time", namespaces = ns )), '')),
                        '%Y-%m-%dT%H:%M:%S'
                    ) -
                    datetime.strptime(
                        str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@start-time", namespaces = ns )), '')),
                        '%Y-%m-%dT%H:%M:%S'
                    )
                ,
                'policy'       : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:profile/@idref", namespaces = ns)), ''),
                'scanner_edition' : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@test-system", namespaces = ns)), ''),
                'title'        : next(iter(tree.xpath("/cdf:Benchmark/cdf:title/text()", namespaces = ns)), ''),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'release'      : release,
                'stigid'       : next(iter(tree.xpath("/cdf:Benchmark/@id", namespaces = ns)), '').split(',')[0],
                'description'  : next(iter(tree.xpath("/cdf:Benchmark/cdf:description/text()", namespaces = ns)), '').split(',')[0],
                'hostname'     : fqdn_val,
                'ip'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), ''),
                'mac'          : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:mac']/text()", namespaces = ns)), ''),
                'device_type'  : '',
                'manufacturer' : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:manufacturer']/text()", namespaces = ns)), ''),
                'model'        : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:model']/text()", namespaces = ns)), ''),
                'serial'       : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:ein']/text()", namespaces = ns)), ''),  
                'os'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:os_version']/text()", namespaces = ns)), ''),
                'credentialed' : Utils.parse_bool(str( next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/@privileged", namespaces = ns)), '') )),
                'scan_user'     : next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/text()", namespaces = ns)), ''),

            })

            for vuln in tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result", namespaces = ns):
                if self.main_app.main_window:
                    QtGui.QGuiApplication.processEvents()
                
                idref = next(iter(vuln.xpath("./@idref", namespaces = ns)), '')

                if str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')).strip() != '':
                    try:
                        descriptionTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        description = str(next(iter(descriptionTree.xpath('/root/VulnDiscussion/text()')), ''))

                        mitigationTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        mitigations = str(next(iter(mitigationTree.xpath('/root/Mitigations/text()')), ''))

                        impactTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        impact = str(next(iter(impactTree.xpath('/root/PotentialImpacts/text()')), ''))

                        resources = []
                        for resource in descriptionTree.xpath('/root/Responsibility/text()'):
                            resources.append(str(resource))
                        resources = ",".join(resources)

                    except:
                        description = ""
                        resources = ""
                        mitigations = ""
                        impact = ""
                else:
                    description = re.search(
                        '<VulnDiscussion>(.*)<\/VulnDiscussion>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    description =  description.group(1) if description is not None else ''

                    resources = re.search(
                        '<Responsibility>(.*)<\/Responsibility>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    resources =  resources.group(1) if resources is not None else ''

                    impact = re.search(
                        '<PotentialImpacts>(.*)<\/PotentialImpacts>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    impact =  impact.group(1) if impact is not None else ''

                    mitigations = re.search(
                        '<Mitigations>(.*)<\/Mitigations>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    mitigations =  mitigations.group(1) if mitigations is not None else ''


                rmf = ""
                ap = ""
                cci = str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:ident[contains(./text(),'CCI')]/text()", namespaces = ns)), ''))
                if cci != '' and self.scar_data.get('data_mapping') is not None:
                    for rmf_cci in self.scar_data.get('data_mapping')['rmf_cci']:
                        if rmf_cci['cci'] == cci:
                            rmf = rmf_cci['control']
                    
                    if cci in self.scar_data.get('data_mapping')['ap_mapping']:
                        ap = self.scar_data.get('data_mapping')['ap_mapping'][cci]
                        
                rule_id = next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_rule_','')
                status = Utils.status(
                    str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), '')) ,
                    'ABBREV'
                )
                            
                sf.add_requirement(
                    ScanRequirement({
                        'vuln_id'        : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_group_',''),
                        'rule_id'        : rule_id,
                        'grp_id'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:title/text()", namespaces = ns)), '') ,
                        'plugin_id'      : '',
                        'rule_ver'       : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:version/text()", namespaces = ns)), '') ,
                        'cci'           : cci,
                        'check_id'       : '',
                        'check_text'     : '',
                        'fix_id'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fix/@id", namespaces = ns)), '') ,
                        'solution'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fixtext/text()", namespaces = ns)), '') ,
                        'mitigation'    : mitigations,
                        'impact'        : impact,
                        'req_title'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:title/text()", namespaces = ns)), '') ,
                        'severity'      : Utils.risk_val(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@severity", namespaces = ns)), '')) ,
                            'NUM'
                        ),
                        'status'        : status,
                        'finding_details': "SCAP scan found this requirement result was '{}'".format(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), ''))
                        ),
                        'comments'      : '',
                        'description'   : description,
                        'ia_controls'    : '',
                        'rmf_controls'   : rmf,
                        'assessments'   : ap,
                        'references'    : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:reference/dc:publisher/text()", namespaces = ns)), '') ,
                        'resources'     : resources,
                    })
                )

        except Exception as e:
            sf = None
            logging.error('Error parsing scap file %s', filename)
            logging.error(str(e))
            print(filename)
            print(str(e))
        return sf

    def parseCkl(self, filename):
        """Parse new CKLB JSON formatted checklists"""
        logging.info('Parsing CKL/CKLB file %s', filename)
        sf = None

        try:
            with open(filename, 'r', encoding='utf-8', errors='replace') as content_file:
                first_line = content_file.readline()
                content_file.seek(0)
                content = content_file.read()

            ext = os.path.splitext(filename)[1].lower()
            is_cklb_json = ext == '.cklb' and first_line.strip().startswith('{')

            if is_cklb_json:
                # --- JSON-based .cklb ---
                data = json.loads(content)
                asset = data.get("target_data", {})
                stig_data = data.get("stigs", [])
                
                # Normalize host identifiers from CKLB
                ip_raw  = str(asset.get("ip_address", "") or "")
                mac_raw = str(asset.get("mac_address", "") or "")
                ip_clean  = ScanUtils.clean_ip(ip_raw)
                mac_clean = ScanUtils.clean_mac(mac_raw)

                fqdn_val = (asset.get("fqdn") or asset.get("host_name") or asset.get("ip_address") or 'UNKNOWN').lower()

                sf = ScanFile({
                    'type': 'CKL',
                    'filename': filename,
                    'scan_date': asset.get("scanDate") or time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(os.path.getmtime(filename))),
                    'duration': '',
                    'scanner_edition': '',
                    'hostname': fqdn_val,
                    'ip': ip_clean,
                    'mac': mac_clean,
                    'os': '',
                    'device_type': '',
                    'manufacturer': '',
                    'model': '',
                    'serial': '',
                    'credentialed': True
                })
                for stig_data in data.get ("stigs", []):
                    rules = stig_data.get("vulns") or stig_data.get("rules", [])
                    for rule in rules:
                        if self.main_app.main_window:
                            QtGui.QGuiApplication.processEvents()

                        cci = (rule.get("cci") or rule.get("ccis", [""])[0])
                        rmf = ""
                        ap = ""
                        if cci and self.scar_data.get('data_mapping'):
                            for rmf_cci in self.scar_data['data_mapping'].get('rmf_cci', []):
                                if rmf_cci['cci'] == cci:
                                    rmf = rmf_cci['control']
                            ap = self.scar_data['data_mapping'].get('ap_mapping', {}).get(cci, "")
                            
                        stig_meta = {
                            'stig_title': stig_data.get("display_name") or stig_data.get("stig_name") or "DISA Security Technical Implementation Guide",
                            'stig_uuid': stig_data.get("uuid", ""),
                            'stig_version': str(stig_data.get("version", "")).split('.')[0],
                            'stig_release': re.search(r"Release:\s*(\d+)", stig_data.get("release_info", "")).group(1) if stig_data.get("release_info") else '0',
                            'stig_stigid': stig_data.get("stig_id", ""),
                            'stig_classification': stig_data.get("classification", "")
                        }
                        # Decode HTML entities in CKLB strings (e.g., &gt; -> >)
                        def clean(val):
                            if not val:
                                return ''
                            s = str(val)
                            # Unescape up to twice to deal with double-encoded values
                            for _ in range(2):
                                new_s = unescape(s)
                                if new_s == s:
                                    break
                                s = new_s
                            # Normalize line breaks
                            return s.replace('\r\n', '\n')

                        sf.add_requirement(ScanRequirement({
                            'vuln_id': rule.get("group_id") or rule.get("vulnNum", ""),
                            'rule_id': rule.get("rule_id") or rule.get("ruleID", ""),
                            'grp_id': clean(rule.get("group_title") or rule.get("groupTitle", "")),
                            'plugin_id': '',
                            'rule_ver': rule.get("rule_version") or rule.get("ruleVer", ""),
                            'cci': cci,
                            'check_id': '',
                            'fix_id': '',
                            'req_title': clean(rule.get("rule_title") or rule.get("ruleTitle", "")),
                            'severity': Utils.risk_val(rule.get("severity", ""), 'NUM'),
                            'status': Utils.status(rule.get("status", ""), 'ABBREV'),
                            'finding_details': clean(rule.get("finding_details", "")),
                            'comments': clean(rule.get("comments", "")),
                            'mitigation': '',
                            'description': clean(rule.get("discussion", "")),
                            'ia_controls': clean(rule.get("ia_controls", "")),
                            'rmf_controls': rmf,
                            'assessments': ap,
                            'check_text': clean(rule.get("check_content", "")),
                            'solution': clean(rule.get("fix_text", "")),
                            'references': clean(rule.get("reference_identifier", "")),
                            'resources': clean(rule.get("responsibility", "")),
                            'title': stig_meta['stig_title'],
                            'uuid': stig_meta['stig_uuid'],
                            'version': stig_meta['stig_version'],
                            'release': stig_meta['stig_release'],
                            'stigid': stig_meta['stig_stigid'],
                            'classification': stig_meta['stig_classification'],
                        }))

            else:
                # --- Fallback to XML-based .ckl ---
                return self._parse_ckl_xml(content, filename)

        except Exception as e:
            sf = None
            logging.error('Error parsing CKL/CKLB file %s', filename)
            logging.exception(e)

        return sf

    def _parse_ckl_xml(self, content, filename):
        """Helper method to parse legacy .ckl files (XML format)"""
        logging.info('Parsing Legacy CKL file %s', filename)
        sf = None
        try:
            # Load file content (ignore unicode > 127 as before)
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                lines = content_file.readlines()
            start = 0
            if '?' in lines[start]:
                start += 1
            if '!' in lines[start]:
                start += 1

            lines = lines[start:]
            raw = ''.join(lines)
            raw = ''.join([ch if ord(ch) < 128 else ' ' for ch in raw])

            tree = etree.fromstring(str(raw))

            # --- Asset / host identity (unchanged logic, done once) ---
            if next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_FQDN/text()")), ''):
                fqdn_val = str(next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_FQDN/text()")), '')).lower()
            elif next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_NAME/text()")), ''):
                fqdn_val = str(next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_NAME/text()")), '')).lower()
            elif next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), ''):
                fqdn_val = str(next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), '')).lower()
            else:
                fqdn_val = 'UNKNOWN'
                
            # Normalize host identifiers from CKL XML
            ip_raw = next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), '')
            mac_raw = next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_MAC/text()")), '')
            ip_clean  = ScanUtils.clean_ip(str(ip_raw))
            mac_clean = ScanUtils.clean_mac(str(mac_raw))

            # Keep the description behavior as-is (first iSTIG description at file level)
            file_description = next(iter(tree.xpath(
                "/CHECKLIST/STIGS/iSTIG[1]/STIG_INFO/SI_DATA[./SID_NAME='description']/SID_DATA/text()"
            )), '')

            # --- Create ScanFile ONCE (moved out of the iSTIG loop) ---
            sf = ScanFile({
                'type'            : 'CKL',
                'filename'        : str(filename),
                'scan_date'       : time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(os.path.getmtime(filename))),
                'duration'        : '',
                'scanner_edition' : '',
                'description'     : file_description,
                'hostname'        : fqdn_val,
                'ip'              : ip_clean,
                'mac'             : mac_clean,
                'os'              : '',
                'device_type'     : '',
                'manufacturer'    : '',
                'model'           : '',
                'serial'          : '',
                'credentialed'    : True
            })

            # --- Iterate each iSTIG and scope VULN to it ---
            for istig in tree.xpath("/CHECKLIST/STIGS/iSTIG"):
                if self.main_app.main_window:
                    QtGui.QGuiApplication.processEvents()

                # Per‑STIG release (keep existing parsing rules)
                release_text = next(iter(istig.xpath(
                    "./STIG_INFO/SI_DATA[./SID_NAME='releaseinfo']/SID_DATA/text()"
                )), '')
                m_rel = re.search(r'Release:\s*([0-9\*.]+)\s+Benchmark', release_text)
                stig_release = m_rel.group(1) if m_rel else '0'
                if '.' in stig_release:
                    # Keep existing behavior of taking the part after the dot
                    stig_release = stig_release.split('.', 1)[1]
                if stig_release.isdigit():
                    stig_release = str(int(stig_release))

                # Per‑STIG version (keep split-on-dot, coerce if numeric)
                stig_version = str(next(iter(istig.xpath(
                    "./STIG_INFO/SI_DATA[./SID_NAME='version']/SID_DATA/text()"
                )), ''))
                if '.' in stig_version:
                    stig_version = stig_version.split('.', 1)[0]
                if stig_version.isdigit():
                    stig_version = str(int(stig_version))

                # Per‑STIG metadata
                stig_meta = {
                    'stig_title'        : next(iter(istig.xpath("./STIG_INFO/SI_DATA[./SID_NAME='title']/SID_DATA/text()")), '') or "DISA Security Technical Implementation Guide",
                    'stig_uuid'         : next(iter(istig.xpath("./STIG_INFO/SI_DATA[./SID_NAME='uuid']/SID_DATA/text()")), ''),
                    'stig_stigid'       : next(iter(istig.xpath("./STIG_INFO/SI_DATA[./SID_NAME='stigid']/SID_DATA/text()")), ''),
                    'stig_classification': next(iter(istig.xpath("./STIG_INFO/SI_DATA[./SID_NAME='classification']/SID_DATA/text()")), '')
                }

                # Only VULN elements under this iSTIG
                for vuln in istig.xpath(".//VULN"):
                    if self.main_app.main_window:
                        QtGui.QGuiApplication.processEvents()

                    rmf = ""
                    ap = ""
                    cci = str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='CCI_REF']/ATTRIBUTE_DATA/text()")), ''))

                    if cci and self.scar_data.get('data_mapping') is not None:
                        for rmf_cci in self.scar_data.get('data_mapping')['rmf_cci']:
                            if rmf_cci['cci'] == cci:
                                rmf = rmf_cci['control']
                                break
                        if cci in self.scar_data.get('data_mapping')['ap_mapping']:
                            ap = self.scar_data.get('data_mapping')['ap_mapping'][cci]

                    rule_id = next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA/text()")), '')
                    status = Utils.status(next(iter(vuln.xpath("./STATUS/text()")), ''), 'ABBREV')

                    sf.add_requirement(ScanRequirement({
                        'vuln_id'        : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), ''),
                        'rule_id'        : rule_id,
                        'grp_id'         : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Group_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'plugin_id'      : '',
                        'rule_ver'       : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Ver']/ATTRIBUTE_DATA/text()")), ''),
                        'cci'            : cci,
                        'check_id'       : '',
                        'fix_id'         : '',

                        'req_title'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'severity'       : Utils.risk_val(
                            str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Severity']/ATTRIBUTE_DATA/text()")), '')),
                            'NUM'
                        ),
                        'status'         : status,
                        'finding_details': next(iter(vuln.xpath("./FINDING_DETAILS/text()")), ''),
                        'comments'       : next(iter(vuln.xpath("./COMMENTS/text()")), ''),
                        'mitigation'     : '',

                        'description'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Discuss']/ATTRIBUTE_DATA/text()")), ''),
                        'ia_controls'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='IA_Controls']/ATTRIBUTE_DATA/text()")), ''),
                        'rmf_controls'   : rmf,
                        'assessments'    : ap,
                        'check_text'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Check_Content']/ATTRIBUTE_DATA/text()")), ''),
                        'solution'       : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Fix_Text']/ATTRIBUTE_DATA/text()")), ''),
                        'references'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='STIGRef']/ATTRIBUTE_DATA/text()")), ''),
                        'resources'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Responsibility']/ATTRIBUTE_DATA/text()")), ''),

                        # Per‑STIG fields applied here:
                        'title'          : stig_meta['stig_title'],
                        'uuid'           : stig_meta['stig_uuid'],
                        'version'        : stig_version,
                        'release'        : stig_release,
                        'stigid'         : stig_meta['stig_stigid'],
                        'classification' : stig_meta['stig_classification'],
                    }))

        except Exception as e:
            logging.error('Error parsing legacy CKL (XML) %s', filename)
            logging.exception(e)
            return None

        return sf