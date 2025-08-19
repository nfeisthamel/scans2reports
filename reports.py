""" reports module of scans to poam"""
# pylint: disable=C0301
import re
import sys
import pprint
import os.path
import string
import datetime
import logging
import jmespath
import pickle
import json
import datetime
import ipaddress
import math
import os

from scar_pickles import SCARPickles
from collections.abc import Iterable
from collections import defaultdict

from PyQt5 import QtCore, QtGui, QtWidgets
from functools import reduce
from dateutil import parser

from threading import Thread
from queue import Queue

import xlsxwriter
import psutil
from utils import Utils
from scan_utils import ScanUtils

from xlsxwriter.utility import xl_col_to_name


import time

class Reports:
    """ reports class of scans to reports """
    workbook = None
    scan_results = []
    
    strings = {
        'STIG' : 'Security Technical Implementation Guide',
        'IGN_SOFT' : r'/drivers|drv|driver|lib|library|framework|patch|update|runtime|chipset|redistributable|kb[0-9]+'
    }

    def __init__(self, main_window=None):
        """ constructor """
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        
        self.scar_conf = SCARPickles.loader( os.path.join(application_path, "data", "scar_configs.pkl") )
        self.scar_data = SCARPickles.loader( os.path.join(application_path, "data", "scar_data.pkl") )
        
        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{self.scar_conf.get('application_path')}/scans2reports.log", level=logging.INFO, format=FORMAT)
        logging.info('Building Reports Object')
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "results",
            f"scans2reports-{timestamp}"
        )
        os.makedirs(self.report_dir, exist_ok=True)
        report_name = os.path.join(self.report_dir, f"scans2reports.xlsx")
        # report_name = "{}/results/{}".format(
            # os.path.dirname(os.path.realpath(__file__)),
            # datetime.datetime.now().strftime("scans2reports-%Y%m%d_%H%M%S.xlsx")
        # )

        self.workbook = xlsxwriter.Workbook(report_name)
        self.main_window = main_window
        self.generated_sheets = []
        
        self.STATE_OK = {"LISTENING", "ESTABLISHED", "TIME_WAIT"}
        
        #Loads lists.json
        
        self.dropdown_data = {}
        self.defined_names = {}
        
        dropdown_path = os.path.join(self.scar_conf.get('application_path'), 'data', 'lists.json')
        if os.path.exists(dropdown_path):
            with open(dropdown_path, 'r', encoding='utf-8') as f:
                self.dropdown_data = json.load(f)
            
        # Creates hidden "Lists" tab and formats it
        
            self.dropdown_sheet = self.workbook.add_worksheet('(U) Lists')
            self.generated_sheets.append('(U) Lists')
            self.dropdown_sheet.hide()
        
            col_idx = 0
        
            for list_name, values in self.dropdown_data.items():
                col_letter = xl_col_to_name(col_idx)
                for row_idx, val in enumerate(values):
                    self.dropdown_sheet.write(row_idx, col_idx, val)
                range_name = f"{list_name.replace(' ', '')}"
                self.workbook.define_name(
                    range_name, 
                    f'=\'(U) Lists\'!${col_letter}$1:${col_letter}${len(values)}'
                )
                self.defined_names[list_name] = range_name
                col_idx += 1
                
        # Setup header data for all functions
        
        self.exported_date = datetime.datetime.now().strftime("%Y%m%d")
        # self.exported_by = self.scar_data.get('name', '')
        self.office_org = self.scar_data.get('command', '')
        self.poc_name = self.scar_data.get('name', '')
        self.poc_phone = self.scar_data.get('phone', '')
        self.poc_email = self.scar_data.get('email', '')
        self.systemname = self.scar_data.get('systemname', '')
        self.apmsid = self.scar_data.get('apmsid', '')
        self.reviewed = self.scar_data.get('reviewed', '')

    def close_workbook(self):
        """ Close the excel file """
        logging.info('Closing Workbook')
        self.workbook.close()

    def close_hwsw_workbook(self):
        """Close the HWSW workbook if it exists"""
        if hasattr(self, 'hwsw_workbook'):
            logging.info('Closing HWSW workbook')
            self.hwsw_workbook.close()
 
    def close_ppsm_workbook(self):
        """Close the HWSW workbook if it exists"""
        if hasattr(self, 'ppsm_workbook'):
            logging.info('Closing PPS workbook')
            self.ppsm_workbook.close()
            
    def close_poam_workbook(self):
        """Close the POA&M workbook if it exists"""
        if hasattr(self, 'poam_workbook'):
            logging.info('Closing POA&M workbook')
            self.poam_workbook.close()

    def rpt_scap_ckl_issues(self):
        """ SCAP - CKL Inconsistencies tab """
        if 'rpt_scap_ckl_issues' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building SCAP-CKL Inconsistencies report')
        worksheet = self.workbook.add_worksheet('SCAP-CKL Inconsistencies')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'SCAP-CKL Inconsistencies' Tab")

        widths = [40, 40, 15, 15, 15, 15, 35, 35, 25, 25, 25, 25, 20, 20, 75, 75, 75, 150]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)
        report = []

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
    
        scaps = jmespath.search(
            "results[?type=='SCAP'].{ scan_title: title, version: version, release: release, filename: filename, requirements: requirements[] | [*].{ req_title: req_title, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, comments: comments } }",
            { 'results' : scan_results}
        )
        ckls = jmespath.search(
            "results[?type=='CKL'].{ scan_title: title, version: version, release: release, filename: filename, requirements: requirements[] | [*].{ req_title: req_title, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, comments: comments } }",
            { 'results' : scan_results}
        )
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        mismatch = []

        print("        {} - Finding Non-Executed CKL requirements".format( datetime.datetime.now() - start_time ))
        executed_ckls = list(set(jmespath.search("results[].requirements[].vuln_id[]", { 'results' : ckls} )))

        for scap in scaps:
            start_time2 = datetime.datetime.now()
            for req in scap['requirements']:
                if req['vuln_id'] not in executed_ckls:
                    c = {
                        'Scan Title'          : scap['scan_title'].replace(self.strings['STIG'], 'STIG'),
                        'Req Title'           : req['req_title'],
                        'SCAP Version'        : int(str(scap['version'])),
                        'SCAP Release'        : int(str(scap['release'])),
                        'CKL Version'         : '',
                        'CKL Release'         : '',
                        'SCAP Grp_Id'          : req['grp_id'],
                        'CKL Grp_Id'           : '',
                        'SCAP Rule_Id'         : req['rule_id'],
                        'CKL Rule_Id'          : '',
                        'SCAP Vuln_Id'         : req['vuln_id'],
                        'CKL Vuln_Id'          : '',
                        'SCAP Status'         : Utils.status(req['status'], 'HUMAN'),
                        'CKL Status'          : 'Not Executed',
                        'SCAP Filename'       : os.path.basename(scap['filename']),
                        'CKL Filename'        : '',
                        'CKL Finding Details' : '',
                        'CKL Comments'        : ''
                    }
                    mismatch.append(c)
        print( "        {} - Finished Non-Executed CKL search".format(datetime.datetime.now() - start_time ) )
        
        print( "        {} - Compiling CKL/SCAP status mismatches".format(datetime.datetime.now() - start_time ) )
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        disa_scans = jmespath.search(
            """results[?type == 'CKL' || type == 'SCAP'].{
                type: type,
                scan_title: title,
                filename: filename, 
                version: version, 
                release: release, 
                requirements: requirements[*].{
                    req_title: req_title,
                    grp_id: grp_id,
                    rule_id: rule_id,
                    vuln_id: vuln_id,
                    status: status,
                    comments: comments,
                    finding_details: finding_details
                }
            }""",
            { 'results' : scan_results}
        )
        
        findings = []
        for scan in disa_scans:
            for req in scan['requirements']:
                findings.append({
                    'scan_title'      : scan['scan_title'],
                    'type'            : scan['type'],
                    'filename'        : scan['filename'],
                    'version'         : scan['version'],
                    'release'         : scan['release'],
                    'req_title'       : req['req_title'],
                    'grp_id'          : req['grp_id'],
                    'rule_id'         : req['rule_id'],
                    'vuln_id'         : req['vuln_id'],
                    'status'          : req['status'],
                    'finding_details' : req['finding_details'],
                    'comments'        : req['comments']
                })
        print("        {} - Analyzing {} scan results".format(datetime.datetime.now() - start_time, len(findings) ))
        
        open_scap_findings = list(set( jmespath.search("results[?type == 'SCAP' && (status == 'O' || status == 'E' )].vuln_id" , { 'results' : findings }) ))
        closed_ckl_findings = list(set( jmespath.search("results[?type == 'CKL' && status != 'O'].vuln_id" , { 'results' : findings }) ))
        mismatched_scans = sorted( list( set(open_scap_findings) & set(closed_ckl_findings) ) )
        
        print("        {} - Found {} mismatched scan results".format(datetime.datetime.now() - start_time, len(mismatched_scans) ))
        
        index = 0
        total = len(mismatched_scans)
        for mismatched_scan in mismatched_scans:
            index += 1
            if index % 100 == 0:
                print("        {} - {} percent complete".format(datetime.datetime.now() - start_time,  round( index / total *100  ,2) ))
            
            for scap in jmespath.search("results[?type == 'SCAP' && (status == 'O' || status == 'E' ) && vuln_id == '" + mismatched_scan + "']", { 'results' : findings } ):
                for ckl in jmespath.search("results[?type == 'CKL' && status != 'O' && vuln_id == '" + mismatched_scan + "']", { 'results' : findings } ):
                    c = {
                        'Scan Title'          : scap['scan_title'].replace(self.strings['STIG'], 'STIG'),
                        'Req Title'           : scap['req_title'],
                        'SCAP Version'        : int(str(scap['version'])),
                        'SCAP Release'        : int(str(scap['release'])),
                        'CKL Version'         : int(str(ckl['version'])),
                        'CKL Release'         : int(str(ckl['release'])),
                        'SCAP Grp_Id'         : scap['grp_id'],
                        'CKL Grp_Id'          : ckl['grp_id'],
                        'SCAP Rule_Id'         : scap['rule_id'],
                        'CKL Rule_Id'          : ckl['rule_id'],
                        'SCAP Vuln_Id'         : scap['vuln_id'],
                        'CKL Vuln_Id'          : ckl['vuln_id'],
                        'SCAP Status'         : Utils.status(scap['status'], 'HUMAN'),
                        'CKL Status'          : Utils.status(ckl['status'], 'HUMAN'),
                        'SCAP Filename'       : os.path.basename(scap['filename']),
                        'CKL Filename'        : os.path.basename(ckl['filename']),
                        'CKL Finding Details' : ckl['finding_details'],
                        'CKL Comments'        : ckl['comments']
                    }
                    mismatch.append(c)
        
        print( "        {} - Finished mismatch search".format(datetime.datetime.now() - start_time ) )
        print( "        Generating Tab")
        report = sorted(mismatch, key=lambda s: (str(
            s['Scan Title']).lower().strip(),
            str(s['SCAP Status']).lower().strip(),
            str(s['SCAP Vuln_Id']).lower().strip(),
            str(s['SCAP Rule_Id']).lower().strip(),
            str(s['Req Title']).lower().strip(),
        ))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'justify', 'valign':'top'})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], cell_format)
                    col += 1
                row += 1

    def rpt_test_plan(self):
        """ Generates Test Plan """
        if 'rpt_test_plan' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Test Plan Report')
        worksheet = self.workbook.add_worksheet('Test Plan')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Test Plan' Tab")

        widths = [75,20,50,50,35]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_files = jmespath.search(
            """results[?type == 'ACAS'].{
                type: type,
                version: version,
                feed: feed,
                filename: filename,
                scan_date: scan_date,
                hosts: hosts[] | [*].[hostname][]
            }""",
            { 'results' : scan_results}
        )

        for scan_file in acas_files:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : 'ACAS: Assured Compliance Assessment Solution / Nessus Scanner',
                'Version'        : str(scan_file['version']) + " - " + str(scan_file['feed']),
                'Hosts'          : ", ".join( scan_file['hosts']),
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        scap_files = jmespath.search(
            """results[?type == 'SCAP'].{
                title: title,
                type: type,
                version: version,
                release: release,
                filename: filename,
                scan_date: scan_date,
                hostname: hostname
            }""",
            { 'results' : scan_results}
        )

        for scan_file in scap_files:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : f"{scan_file['type']}: {scan_file['title']}",
                'Version'        : "V" + str(scan_file['version']) + "R" + str(scan_file['release']),
                'Hosts'          : scan_file['hostname'],
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        ckl_files = jmespath.search(
            """results[?type == 'CKL'].{
                title: title,
                type: type,
                version: version,
                release: release,
                filename: filename,
                scan_date: scan_date,
                hostname: hostname
            }""",
            { 'results' : scan_results}
        )

        for scan_file in ckl_files:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : f"{scan_file['type']}: {scan_file['title']}",
                'Version'        : "V" + str(scan_file['version']) + "R" + str(scan_file['release']),
                'Hosts'          : scan_file['hostname'],
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        report = sorted(report, key=lambda s: (str(s['Title']).lower().strip(), str(s['Version']).lower().strip(), str(s['Hosts']).lower().strip()))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_poam(self):
        """ Generates POAM """
        if 'rpt_poam' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building POAM')
        worksheet = self.workbook.add_worksheet('POA&M')
        self.generated_sheets.append('POA&M')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'POAM' Tab")
            QtGui.QGuiApplication.processEvents()

        widths = [1,20,40,15,25,25,25,30,15,30,45,20,30,25,75,40,40,25,25,40,25,25,40,25,40,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(6, 0, 6, int(len(widths))-1)

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        q = Queue(maxsize=0)
        poam_results = {'O'  : {}, 'NA' : {}, 'NR' : {}, 'E'  : {}, 'C'  : {}}

        def get_scan(queue, poam_results, scan_results):
            while not queue.empty():
                work = queue.get()

                status = work[0]
                type = work[1]
                if type == 'disa':
                    disa_scans = jmespath.search(
                        "results[?type=='SCAP' || type=='CKL'].{ policy: policy, scanner_edition: scanner_edition, scan_description: description, type: type, hostname: hostname, filename: filename, requirements: requirements[] | [?status=='" + status + "'].{ req_title: req_title, cci: cci, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, description: description, version: version, release: release, stig_id: stigid, stig_uuid: uuid, stig_classification: classification, scan_title: title } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['rule_id']) not in poam_results[status]:
                                poam_results[status][str(req['rule_id'])] = {
                                    'scan_title'      : req['scan_title'],
                                    'grp_id'          : req['grp_id'],
                                    'vuln_id'         : req['vuln_id'],
                                    'rule_id'         : req['rule_id'],
                                    'plugin_id'       : req['plugin_id'],
                                    'cci'             : req['cci'],
                                    'iavm'            : '',
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['rule_id']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scanner_edition'],
                                'hostname'        : scan['hostname'],
                                'version'         : req['version'],
                                'release'         : req['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scanner_edition: '', scan_description: '', type: type, version: version, release: feed, filename: filename, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [?status=='" + status + "'].{ cci: cci, req_title: req_title, description: description, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, iavm: iavm, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, publication_date: publication_date, modification_date: modification_date, rmf_controls: rmf_controls } } }",
                        { 'results' : scan_results}
                    )
                    
                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                # debugging
                                # logging.debug(f"[ACAS] Plugin ID: {req.get('plugin_id')}")
                                # logging.debug(f"[ACAS] GRP_ID: {req.get('grp_id')}")
                                # logging.debug(f"[ACAS] CCI: {req.get('cci')}")
                                # logging.debug(f"[ACAS] RMF Controls: {req.get('rmf_controls')}")
                                # logging.debug(f"[ACAS] Requirement Keys: {list(req.keys())}")
                                if 'rmf_controls' not in req:
                                    logging.warning(f"[ACAS] Missing 'rmf_controls' for plugin {req.get('plugin_id')}")
                                elif not isinstance(req['rmf_controls'], list):
                                    logging.warning(f"[ACAS] 'rmf_controls' not a list for plugin {req.get('plugin_id')}: {req.get('rmf_controls')}")

                                if str(req['plugin_id']) not in poam_results[status]:
                                    poam_results[status][str(req['plugin_id'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grp_id'],
                                        'vuln_id'         : req['vuln_id'],
                                        'rule_id'         : req['rule_id'],
                                        'plugin_id'       : req['plugin_id'],
                                        'cci'             : req['cci'],
                                        'iavm'            : req['iavm'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'publication_date'  : req['publication_date'],
                                        'modification_date' : req['modification_date'],
                                        'rmf_controls'      :(req['rmf_controls'][0] if 'rmf_controls' in req and isinstance(req['rmf_controls'], list) and req['rmf_controls']else self.scar_data.get('acas_control', {}).get(req.get('grp_id', ''), '')),
                                        'results'         : [],
                                    }
                                    # logging.debug(f"[RMF FINAL] Plugin ID: {req['plugin_id']} | Family: {req['grp_id']} | RMF: {poam_results[status][str(req['plugin_id'])]['rmf_controls']}")

                                poam_results[status][ str(req['plugin_id']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scanner_edition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_threads = int(psutil.cpu_count()) * 2
        for i in range(num_threads):
            worker = Thread(target=get_scan, args=(q, poam_results, scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )


        selected_mitigations = {}
        if self.scar_data.get('mitigations') is not None and len(self.scar_data.get('mitigations')) >0 and 'mitigations' in self.scar_data.get('mitigations').keys():
            for mit in self.scar_data.get('mitigations')['mitigations']:
                if mit['plugin_id'] is not None and mit['plugin_id'].strip() != '':
                    selected_mitigations[ str(mit['plugin_id']) ] = mit['mitigation']
                if mit['vuln_id'] is not None and mit['vuln_id'].strip() != '':
                    selected_mitigations[ str(mit['vuln_id']) ] = mit['mitigation']
                if mit['rule_id'] is not None and mit['rule_id'].strip() != '':
                    selected_mitigations[ str(mit['rule_id']) ] = mit['mitigation']
                        
        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]
                
                rmf_controls = req.get('rmf_controls', '')
                if rmf_controls == '':
                    rmf_controls = req.get('rmf_controls') or self.scar_data.get('data_mapping', {}).get('ap_mapping', {}).get(req['cci'], '')

                hosts = []
                types = []
                comments = []
                finding_details = []
                for host in req['results']:
                    if self.scar_conf.get('host_details'):
                        hosts.append(f"{host['hostname']} [{host['type']} - Ver: {host['version']}, Rel/Feed: {host['release']} ]")
                    else:
                        hosts.append(f"{host['hostname']}")
                    
                    types.append(f"{host['type']}")
                    comments.append(f"{host['comments']}")
                    finding_details.append(f"{host['finding_details']}")

                hosts = "\n".join(hosts)
                types = list(set(types))
                prefix = "/".join(types)
                comments = "\n\n".join( list(set([c for c in comments if c])) )
                finding_details = "\n\n".join( list(set([f for f in finding_details if f])) )

                # pylint: disable=C0330
                scd = ""
                if self.scar_conf.get('scd'):
                    if self.scar_conf.get('lower_risk'):
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                    else:
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )
                else:
                    scd = ''

                predisposing_conditions = self.scar_conf.get('predisposing_conditions')
                
                mitigation_statement = ''
                if self.scar_conf.get('mitigation_statements') == 'poam':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                elif self.scar_conf.get('mitigation_statements') == 'ckl' and 'ckl' in req['results'][0]['type'].lower():
                    mitigation_statement = comments
                elif self.scar_conf.get('mitigation_statements') == 'both':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                    if mitigation_statement.strip() == '' and 'ckl' in req['results'][0]['type'].lower():
                        mitigation_statement = comments
                
                if self.scar_conf.get('test_results') is not None:
                    #test results parsed
                    
                    if req['cci'].strip() != '':
                        #cci is present
                        
                        if(
                            self.scar_conf.get('test_results') == 'add' or
                            (
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str)
                            )
                        ):
                            #add option selected, proceed as normal
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            
                        elif self.scar_conf.get('test_results') == 'close':
                            #close option selected, inheritted or CCI's not in package will be closed.
                            #non-inheritted controls that are present will proceed as normal
                            
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and 
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to close
                                comments = f"{ req['cci']}\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being marked as 'Completed' by default. \n\n{comments}"
                                rmf_controls = rmf_controls
                                status = f"{ Utils.status('C', 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"{ req['cci']}\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being marked as completed by default. \n\n{comments}"
                                    rmf_controls = rmf_controls
                                    status = f"{ Utils.status('C', 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        elif self.scar_conf.get('test_results') == 'convert':
                            #convert option selected, inheritted or CCI's not in package will be converted to CM-6.5
                            #non-inheritted controls that are present will proceed as normal
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and 
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to CM-6.5
                                comments = f"CCI-000366\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being mapped to CCI-000366 CM-6.5.\n\n{comments}"
                                req['cci'] = 'CCI-000366'
                                rmf_controls = "CM-6.5"
                                status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"CCI-000366\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being mapped to CCI-000366 CM-6.5. \n\n{comments}"
                                    req['cci'] = 'CCI-000366'
                                    rmf_controls = "CM-6.5"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        else:
                            #fallthrough catch.  This should never be reached
                            
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    else:
                        #no cci present, convert to CM-6.5
                        rmf_controls = 'CM-6.5'
                        req['cci'] = 'CCI-000366'
                        comments = f"{req['cci']}\n\nThe control mapping for this requirement is unavailable so it is being mapped to CCI-000366 CM-6.5 by default. \n\n{comments}"
                        status = f"{ Utils.status(req['status'], 'HUMAN') }"

                else:
                    # logging.debug(f"[REPORT] Plugin family: {req.get('grp_id')}, RMF Control: {rmf_controls}")
                    # test results not submitted, process as usual
                    rmf_controls = rmf_controls
                    comments = f"{ req['cci']}\n\n{comments}"
                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    
                if self.scar_conf.get('include_finding_details'):
                    comments = f"{comments}\n\nFinding Details:\n{finding_details}"
                
                req_data = {
                    'A'                                                 : '',
                    'POA&M Item ID'                                     : '',
                    'Control Vulnerability Description'                 : f"Title: {req['req_title']}\n{req['iavm']}\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Security Control Number (NC/NA controls only)'     : rmf_controls,
                    'Office/Org'                                        : f"{self.scar_data.get('command')}\n{self.scar_data.get('name')}\n{self.scar_data.get('phone')}\n{self.scar_data.get('email')}\n".strip(),
                    'Security Checks'                                   : f"{req['plugin_id']}{req['rule_id']}\n{req['vuln_id']}",
                    'Resources Required'                                : f"{req['resources']}",
                    'Scheduled Completion Date'                         : scd,
                    'Milestone with Completion Dates'                   : "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
                                                                                                                        s=str(scd).split('-'),
                                                                                                                        m=(['Quarter One', 'Quarter Two', 'Quarter Three', 'Quarter Four'][((int(str(scd).split('-')[1]) -1 )//3)]),
                                                                                                                    ) if self.scar_conf.get('scd') else '',
                    'Milestone Changes'                                 : '',
                    'Source Identifying Control Vulnerability'          : f"{prefix} {req['scan_title']}",
                    'Status'                                            : status,
                    'Comments'                                          : comments,
                    'Raw Severity'                                      : Utils.risk_val(req['severity'], 'MIN'),
                    'Devices Affected'                                  : hosts,
                    'Mitigations'                                       : mitigation_statement,
                    'Predisposing Conditions'                           : predisposing_conditions,
                    'Severity'                                          : Utils.risk_val(req['severity'], 'POAM'),
                    'Relevance of Threat'                               : 'High',
                    'Threat Description'                                : req['description'],
                    'Likelihood'                                        : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact'                                            : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact Description'                                : '',
                    'Residual Risk Level'                               : Utils.risk_val(req['severity'], 'POAM'),
                    'Recommendations'                                   : req['solution'],
                    'Resulting Residual Risk after Proposed Mitigations': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.scar_conf.get('lower_risk') else Utils.risk_val(req['severity'], 'POAM'),
                }


                if 'publication_date' not in req:
                    report.append(req_data)
                elif req['publication_date'] is None:
                    report.append(req_data)
                elif( str(req['publication_date']).strip() == '' ):
                    report.append(req_data)
                elif( datetime.datetime.strptime(req['publication_date'],'%Y/%m/%d')  < datetime.datetime.today() - datetime.timedelta(days=self.scar_conf.get('exclude_plugins') ) ):
                    report.append(req_data)

                            
                    
                # pylint: enable=C0330
        print( "        {} - Generating POAM".format(datetime.datetime.now() - start_time) )
        row = 6
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'left', 'valign':'top'})
        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 8, 'align': 'justify', 'valign':'top'})

        if report:
            report = sorted(report, key=lambda s: (
                str(s['Status']).lower().strip(),
                str(s['Source Identifying Control Vulnerability']).lower().strip(),
                str(s['Security Checks']).lower().strip()
            ))
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, str(result[value]).strip(), date_fmt)
                    else:
                        worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    col += 1
                row += 1
        print( "        {} - Finished generating POAM".format(datetime.datetime.now() - start_time) )

    def rpt_rar(self):
        """ Generates RAR """
        #TODO Update
        if 'rpt_rar' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building RAR')
        worksheet = self.workbook.add_worksheet('RAR')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'RAR' Tab")
            QtGui.QGuiApplication.processEvents()

        widths = [15,15,45,30,30,45,20,15,30,30,15,15,30,30,15,15,15,15,30,30,45,30]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        q = Queue(maxsize=0)
        poam_results = {'O'  : {}, 'NA' : {}, 'NR' : {}, 'E'  : {}, 'C'  : {}}

        def get_scan(queue, poam_results, scan_results):
            while not queue.empty():
                work = queue.get()

                status = work[0]
                type = work[1]
                if type == 'disa':
                    disa_scans = jmespath.search(
                        "results[?type=='SCAP' || type=='CKL'].{ policy: policy, scanner_edition: scanner_edition, scan_description: description, type: type, hostname: hostname, filename: filename, requirements: requirements[] | [?status=='" + status + "'].{ req_title: req_title, cci: cci, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, description: description, version: version, release: release, stig_id: stigid, stig_uuid: uuid, stig_classification: classification, scan_title: title } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['rule_id']) not in poam_results[status]:
                                poam_results[status][str(req['rule_id'])] = {
                                    'scan_title'      : req['scan_title'],
                                    'grp_id'          : req['grp_id'],
                                    'vuln_id'         : req['vuln_id'],
                                    'rule_id'         : req['rule_id'],
                                    'plugin_id'       : req['plugin_id'],
                                    'cci'             : req['cci'],
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['rule_id']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scanner_edition'],
                                'hostname'        : scan['hostname'],
                                'version'         : req['version'],
                                'release'         : req['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scanner_edition: '', scan_description: '', type: type, version: version, release: feed, filename: filename, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [?status == '" + status + "'].{ cci: cci, req_title: req_title, description: description, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, publication_date: publication_date, modification_date: modification_date } } }",
                        { 'results' : scan_results}
                    )

                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                if str(req['plugin_id']) not in poam_results[status]:
                                    poam_results[status][str(req['plugin_id'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grp_id'],
                                        'vuln_id'         : req['vuln_id'],
                                        'rule_id'         : req['rule_id'],
                                        'plugin_id'       : req['plugin_id'],
                                        'cci'             : req['cci'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'publication_date'  : req['publication_date'],
                                        'modification_date' : req['modification_date'],
                                        'results'         : [],
                                    }
                                poam_results[status][ str(req['plugin_id']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scanner_edition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_threads = int(psutil.cpu_count()) * 2
        for i in range(num_threads):
            worker = Thread(target=get_scan, args=(q, poam_results, scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        selected_mitigations = {}
        if self.scar_data.get('mitigations') is not None and len( self.scar_data.get('mitigations') ) >0 and 'mitigations' in self.scar_data.get('mitigations').keys():
            for mit in self.scar_data.get('mitigations')['mitigations']:
                if mit['plugin_id'] is not None and mit['plugin_id'].strip() != '':
                    selected_mitigations[ str(mit['plugin_id']) ] = mit['mitigation']
                if mit['vuln_id'] is not None and mit['vuln_id'].strip() != '':
                    selected_mitigations[ str(mit['vuln_id']) ] = mit['mitigation']
                if mit['rule_id'] is not None and mit['rule_id'].strip() != '':
                    selected_mitigations[ str(mit['rule_id']) ] = mit['mitigation']
                    
                    
        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]
                # print(req)
                hosts = []
                types = []
                comments = []
                finding_details = []
                for host in req['results']:
                    if self.scar_conf.get('host_details'):
                        hosts.append(f"{host['hostname']} [{host['type']} - Ver: {host['version']}, Rel/Feed: {host['release']} ]")
                    else:
                        hosts.append(f"{host['hostname']}")
                        
                    types.append(f"{host['type']}")
                    comments.append(f"{host['comments']}")
                    finding_details.append(f"{host['finding_details']}")

                hosts = "\n".join(hosts)
                types = list(set(types))
                prefix = "/".join(types)
                comments = "\n\n".join( list(set([c for c in comments if c])) )
                finding_details = "Finding Details:\n" + "\n\n".join( list(set([f for f in finding_details if f])) )

                # rmf_controls = self.scar_data.get('data_mapping')['acas_control'][req['grp_id']] if req['grp_id'] in self.scar_data.get('data_mapping')['acas_control'] else ''
                # if rmf_controls == '':
                    # rmf_controls = self.scar_data.get('data_mapping')['ap_mapping'][req['cci']] if req['cci'] in self.scar_data.get('data_mapping')['ap_mapping'] else ''
                
                rmf_controls = req.get('rmf_controls', '')
                if rmf_controls == '':
                    rmf_controls = self.scar_data.get('data_mapping')['ap_mapping'].get(req['cci'], '')


                objectives = []
                for rmf_cia in self.scar_data.get('data_mapping')['rmf_cia']:
                    if rmf_controls.strip() != '' and rmf_cia['Ctl'] == rmf_controls:
                        if rmf_cia['CL'] == 'X' or rmf_cia['CM'] == 'X' or rmf_cia['CH'] == 'X':
                            objectives.append('C')
                        if rmf_cia['IL'] == 'X' or rmf_cia['IM'] == 'X' or rmf_cia['IH'] == 'X':
                            objectives.append('I')
                        if rmf_cia['AL'] == 'X' or rmf_cia['AM'] == 'X' or rmf_cia['AH'] == 'X':
                            objectives.append('A')

                objectives = list(set(objectives))
                objectives = ", ".join( objectives )

                mitigation_statement = ''
                if self.scar_conf.get('mitigation_statements') == 'poam':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                elif self.scar_conf.get('mitigation_statements') == 'ckl' and 'ckl' in req['results'][0]['type'].lower():
                    mitigation_statement = comments
                elif self.scar_conf.get('mitigation_statements') == 'both':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                    if mitigation_statement.strip() == '' and 'ckl' in req['results'][0]['type'].lower():
                        mitigation_statement = comments

                if self.scar_conf.get('test_results') is not None:
                    #test results parsed
                    
                    if req['cci'].strip() != '':
                        #cci is present
                        
                        if(
                            self.scar_conf.get('test_results') == 'add' or
                            (
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str)
                            )
                        ):
                            #add option selected, proceed as normal
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            
                        elif self.scar_conf.get('test_results') == 'close':
                            #close option selected, inheritted or CCI's not in package will be closed.
                            #non-inheritted controls that are present will proceed as normal
                            
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and 
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to close
                                comments = f"{ req['cci']}\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being marked as 'Completed' by default. \n\n{comments}"
                                rmf_controls = rmf_controls
                                status = f"{ Utils.status('C', 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"{ req['cci']}\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being marked as completed by default. \n\n{comments}"
                                    rmf_controls = rmf_controls
                                    status = f"{ Utils.status('C', 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        elif(
                            isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                            not isinstance(self.scar_data.get('test_result_data'), str) and 
                            self.scar_conf.get('test_results') == 'convert'
                        ):
                            #convert option selected, inheritted or CCI's not in package will be converted to CM-6.5
                            #non-inheritted controls that are present will proceed as normal
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and  
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to CM-6.5
                                comments = f"CCI-000366\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being mapped to CCI-000366 CM-6.5.\n\n{comments}"
                                req['cci'] = 'CCI-000366'
                                rmf_controls = "CM-6.5"
                                status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"CCI-000366\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being mapped to CCI-000366 CM-6.5. \n\n{comments}"
                                    req['cci'] = 'CCI-000366'
                                    rmf_controls = "CM-6.5"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        else:
                            #fallthrough catch.  This should never be reached
                            
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    else:
                        #no cci present, convert to CM-6.5
                        rmf_controls = 'CM-6.5'
                        req['cci'] = 'CCI-000366'
                        comments = f"{req['cci']}\n\nThe control mapping for this requirement is unavailable so it is being mapped to CCI-000366 CM-6.5 by default. \n\n{comments}"
                        status = f"{ Utils.status(req['status'], 'HUMAN') }"

                else:
                    #test results not submitted, process as usual
                    rmf_controls = rmf_controls
                    comments = f"{ req['cci']}\n\n{comments}"
                    status = f"{ Utils.status(req['status'], 'HUMAN') }"


                # pylint: disable=C0330
                req_data = {
                    'Non-Compliant Security Controls (16a)': rmf_controls,
                    'Affected CCI (16a.1)': req['cci'] if isinstance(req['cci'], str) else '',
                    'Source of Discovery(16a.2)': f"Title: {req['scan_title']}",
                    'Vulnerability ID(16a.3)': f"{req['plugin_id']}{req['rule_id']}",
                    'Vulnerability Description (16.b)': f"Title: {req['req_title']}\n\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Devices Affected (16b.1)': hosts,
                    'Security Objectives (C-I-A) (16c)': objectives,
                    'Raw Test Result (16d)': Utils.risk_val(req['severity'], 'CAT'),
                    'Predisposing Condition(s) (16d.1)': str( self.scar_conf.get('predisposing_conditions') ),
                    'Technical Mitigation(s) (16d.2)': '',
                    'Severity or Pervasiveness (VL-VH) (16d.3)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Relevance of Threat (VL-VH) (16e)': 'High',
                    'Threat Description (16e.1)': req['description'],
                    'Likelihood (Cells 16d.3 & 16e) (VL-VH) (16f)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Impact (VL-VH) (16g)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Impact Description (16h)': '',
                    'Risk (Cells 16f & 16g) (VL-VH) (16i)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Proposed Mitigations (From POA&M) (16j)': mitigation_statement,
                    'Residual Risk (After Proposed Mitigations) (16k)': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.scar_conf.get('lower_risk') else Utils.risk_val(req['severity'], 'VL-VH'),
                    'Recommendations (16l)': req['solution'],
                    'Comments': f"Status: { status }\n\nGroup ID: {req['grp_id']}\nVuln ID: {req['vuln_id']}\nRule ID: {req['rule_id']}\nPlugin ID: {req['plugin_id']}\n\n{comments}\n\n{finding_details}"
                }
                
                if 'publication_date' not in req:
                    report.append(req_data)
                elif req['publication_date'] is None:
                    report.append(req_data)
                elif( str(req['publication_date']).strip() == '' ):
                    report.append(req_data)
                elif( datetime.datetime.strptime(req['publication_date'],'%Y/%m/%d')  < datetime.datetime.today() - datetime.timedelta(days=self.scar_conf.get('exclude_plugins') ) ):
                    report.append(req_data)

        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'left', 'valign':'top'})
        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 8, 'align': 'justify', 'valign':'top'})

        if report:
            report = sorted(report, key=lambda s: (
                str(s['Source of Discovery(16a.2)']).lower().strip(),
                str(s['Vulnerability ID(16a.3)']).lower().strip(),
            ))
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, str(result[value]).strip(), date_fmt)
                    else:
                        worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    col += 1
                row += 1
        print( "        {} - Finished generating RAR".format(datetime.datetime.now() - start_time) )

    def rpt_software_linux(self):
        """ Generates Linux Software Tab """
        if 'rpt_software_linux' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Generating Linux Software Tab')
        
        worksheet = self.workbook.add_worksheet('Software - Linux')
        self.generated_sheets.append('Software - Linux')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Software - Linux' Tab")

        widths = [45, 31, 33, 31, 24, 28, 25, 24, 37, 40, 30, 39, 21, 39, 44, 43, 34, 31, 21, 24, 28, 22, 36, 28, 26, 26, 27, 26, 27, 36, 43, 44, 26, 27]
        def colnum_to_excel_col(n):
            name = ''
            while n >= 0:
                name = chr(n % 26 + ord('A')) + name
                n = n // 26 - 1
            return name

        for index, w in enumerate(widths):
            col_letter = colnum_to_excel_col(index)
            worksheet.set_column(f"{col_letter}:{col_letter}", w)

        worksheet.autofilter(6, 0, 6, len(widths)-1)

        software = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?plugin_id == `22869`]  | [*].{ 
                        plugin_id: plugin_id,
                        comments: comments
                    }
                }
            }""",
            { 'results' : scan_results}
        )
         
        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                host_base_names = set()
                for req in host['requirements']:
                    comments = req.get('comments', '')
                    if not comments:
                        continue

                    for line in filter(None, comments.split("\n")):
                        line = line.strip()
                        if 'list of packages installed' in line:
                            continue

                        # Try RPM/yum-style first: name-version-release|...
                        pkg_match = re.match(r'^(.+)-([0-9][^-]*)-([^-|]+)\|', line)
                        if pkg_match:
                            name, version, release = pkg_match.groups()
                        else:
                            # Fallback for Debian/Ubuntu dpkg -l lines:
                            # e.g., "ii   xserver-xorg  1:7.7+23  amd64  X.Org X server"
                            dpkg_match = re.match(r'^[a-z]{2}\s+(\S+)\s+(\S+)\s+(\S+)\s+.+$', line, re.IGNORECASE)
                            if dpkg_match:
                                name, version, _arch = dpkg_match.groups()
                                release = ''  # not present in dpkg format
                            else:
                                logging.warning(f"Could not parse package line: {line}")
                                continue
                        if re.search(self.strings['IGN_SOFT'], name):
                            continue
                            # Filter sub-modules 
                            
                        base_name = name.split('-')[0] if '-' in name else name
                        if '-' in name and base_name in host_base_names:
                            continue
                        host_base_names.add(base_name)

                        vendor_match = re.findall(r'\|([^|<]*?)<', line)
                        vendor = vendor_match[0].strip() if vendor_match else ''

                        installed = ''  # Not available in ACAS for Linux packages
                        host_entry = {
                            'installed': installed,
                            'hostname': host['hostname'].strip() or host['ip'].strip(),
                            'ip': host['ip'].strip(),
                            'vendor': vendor
                        }

                        entry = next(
                            (s for s in software if s['name'] == name and s['version'] == version and any(h['ip'] == host_entry['ip'] for h in s['hosts'])), 
                            None
                        )
                        if not entry:
                            software.append({
                                'name': name,
                                'version': version,
                                'vendor': vendor,
                                'hosts': [host_entry]
                            })
                        else:
                            entry['hosts'].append(host_entry)

        report = []
        for soft in filter(lambda x: x['name'], software):
            hostnames = [h['hostname'] for h in soft['hosts'] if h['hostname']]
            installed_dates = [h['installed'] for h in soft['hosts'] if h['installed']]

            parent_system = ''
            if soft['hosts']:
                parent_system = hostnames[0] if hostnames else soft['hosts'][0]['ip']

            report.append({
                '#': '',
                'Software Type': '',
                'Software Vendor': soft['vendor'],
                'Software Name': soft['name'],
                'Version': soft['version'],
                'Parent System': parent_system,
                'Subsystem': '',
                'Network': '',
                'Hosting Environment': '',
                'Software Dependencies': '',
                'Cryptographic Hash': '',
                'In Service Date': ", ".join(sorted(set(installed_dates))),
                'IT Budget UII': '',
                'Fiscal Year (FY)': '',
                'POP End Date': '',
                'License or Contract': '',
                'License Term': '',
                'Cost per License': '',
                'Total Licenses': '',
                'Total License Cost': '',
                'Licenses Used': '',
                'License POC': '',
                'License Renewal Date': '',
                'License Expiration Date': '',
                'Approval Status': '',
                'Approval Date': '',
                'Release Date': '',
                'Maintenance Date': '',
                'Retirement Date': '',
                'End of Life/Support Date': '',
                'Extended End of Life/Support Date': '',
                'Critical Information System Asset?': '',
                'Location': '',
                'Purpose': ''
            })

        report = sorted(report, key=lambda s: (s['Software Name'].lower().strip(), s['Version']))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})


        # ---- Header Section ----
        green_header = self.workbook.add_format({'bold': True, 'align': 'left', 'valign': 'vcenter', 'bg_color': '#007A33', 'font_size': 14, 'font_color': 'white', 'border': 1})
        gray_label = self.workbook.add_format({'bold': True, 'align': 'left', 'valign': 'vcenter', 'font_size': 12, 'bg_color': '#BFBFBF', 'border': 1})
        normal_cell = self.workbook.add_format({'border': 1, 'font_size': 12})
        gray_header_cells = self.workbook.add_format({'bg_color': '#BFBFBF'})
        gray_header_merged = self.workbook.add_format({'bg_color': '#BFBFBF', 'right': 1})

        worksheet.merge_range(0, 0, 0, 33, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            worksheet.write(1, col, '', gray_header_cells)
        worksheet.merge_range(1, 13, 1, 33, '', gray_header_merged)

        worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        worksheet.write(2, 6, 'Office / Org:', gray_label)
        worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            worksheet.write(2, col, '', gray_header_cells)
        worksheet.merge_range(2, 13, 2, 33, '', gray_header_merged)

        worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        worksheet.write(3, 6, 'POC Name:', gray_label)
        worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        worksheet.write(3, 12, '', gray_header_cells)
        worksheet.merge_range(3, 13, 3, 33, '', gray_header_merged)

        worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        worksheet.write(4, 6, 'POC Phone:', gray_label)
        worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        worksheet.write(4, 12, '', gray_header_cells)
        worksheet.merge_range(4, 13, 4, 33, '', gray_header_merged)

        worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            worksheet.write(5, col, '', gray_header_cells)
        worksheet.merge_range(5, 13, 5, 33, '', gray_header_merged)

        # ---- Write Data ----
        row = 6
        bold = self.workbook.add_format({'font_size':12, 'bold': True, 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        wrap_text = self.workbook.add_format({'font_size':11, 'text_wrap': True, 'border': 1})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

        # ---- Dropdowns ----
        if "Yes No" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 31, r, 31, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Yes No"]}',
                    'input_message': 'Select Yes or No for Critical Information System Asset.',
                    'show_input': True,
                    'show_error': True
                })

        if "Software Type" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 1, r, 1, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Software Type"]}',
                    'input_message': 'Select a type or enter a custom value.',
                    'show_input': True,
                    'show_error': True
                })

        if "Approval" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 24, r, 24, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Approval"]}',
                    'input_message': 'Select a type or enter a custom value.',
                    'show_input': True,
                    'show_error': True
                })

    def rpt_software_windows(self):
        """ Generates Windows Software Tab """
        if 'rpt_software_windows' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Windows Software Tab')

        # Create Worksheet
        
        worksheet = self.workbook.add_worksheet('Software - Windows')
        self.generated_sheets.append('Software - Windows')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Software - Windows' Tab")

        # Build tab widths and handle extra tabs

        widths = [45, 31, 33, 31, 24, 28, 25, 24, 37, 40, 30, 39, 21, 39, 44, 43, 34, 31, 21, 24, 28, 22, 36, 28, 26, 26, 27, 26, 27, 36, 43, 44, 26, 27]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            def colnum_to_excel_col(n):
                """Convert column index (0-based) to Excel-style column name."""
                name = ''
                while n >= 0:
                    name = chr(n % 26 + ord('A')) + name
                    n = n // 26 - 1
                return name

            for index, w in enumerate(widths):
                col_letter = colnum_to_excel_col(index)
                worksheet.set_column(f"{col_letter}:{col_letter}", w)

        worksheet.autofilter(6, 0, 6, int(len(widths))-1)

        software = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?plugin_id == `178102`]  | [*].{ 
                        plugin_id: plugin_id,
                        comments: comments
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            if self.main_window:
                    QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    comments = req.get('comments', '')
                    if not comments:
                        continue

                    for block in comments.split("\n\n"):
                        lines = block.strip().split("\n")
                        name = version = installed = vendor = ''

                        for i, line in enumerate(lines):
                            line = line.strip()

                            # Software name
                            if line.startswith('- '):
                                name = line[2:].strip()

                            # Version
                            elif '[DisplayVersion]' in line and i + 1 < len(lines):
                                next_line = lines[i + 1].strip()
                                if next_line.startswith("Raw Value") and ":" in next_line:
                                    parts = next_line.split(":", 1)
                                    if len(parts) > 1:
                                        version = parts[1].strip()

                            # Install Date
                            elif '[InstallDate]' in line and i + 1 < len(lines):
                                next_line = lines[i + 1].strip()
                                if next_line.startswith("Raw Value") and ":" in next_line:
                                    parts = next_line.split(":", 1)
                                    if len(parts) > 1:
                                        raw_date = parts[1].strip()
                                        try:
                                            installed = datetime.datetime.strptime(raw_date, "%Y/%m/%d").strftime("%Y-%m-%d")
                                        except Exception:
                                            installed = ''

                            # Publisher
                            elif '[Publisher]' in line and i + 1 < len(lines):
                                next_line = lines[i + 1].strip()
                                if next_line.startswith("Raw Value") and ":" in next_line:
                                    parts = next_line.split(":", 1)
                                    if len(parts) > 1:
                                        vendor = parts[1].strip()


                            if name and version and re.search(self.strings['IGN_SOFT'], name) is None:
                                entry = next((s for s in software if s['name'] == name and s['version'] == version), None)
                                host_entry = {
                                    'installed': installed,
                                    'hostname': host['hostname'].strip() or host['ip'].strip(),
                                    'ip': host['ip'].strip(),
                                    'vendor': vendor
                                }

                                if not entry:
                                    software.append({
                                        'name': name,
                                        'version': version,
                                        'vendor': vendor,
                                        'hosts': [host_entry]
                                    })
                                else:
                                    entry['hosts'].append(host_entry)



        report = []
        for soft in filter(lambda x: x['name'] != '', software):
            hostnames = [h['hostname'] for h in soft['hosts'] if h['hostname']]
            installed_dates = [h['installed'] for h in soft['hosts'] if h['installed']]

            parent_system = ''
            if soft['hosts']:
                parent_system = hostnames[0] if hostnames else soft['hosts'][0]['ip']

            report.append({
                '#': '',
                'Software Type': '',
                'Software Vendor': soft['vendor'],
                'Software Name': soft['name'],
                'Version': soft['version'],
                'Parent System': parent_system,
                'Subsystem': '',
                'Network': '',
                'Hosting Environment': '',
                'Software Dependencies': '',
                'Cryptographic Hash': '',
                'In Service Date': ", ".join(sorted(set(installed_dates))),
                'IT Budget UII': '',
                'Fiscal Year (FY)': '',
                'POP End Date': '',
                'License or Contract': '',
                'License Term': '',
                'Cost per License': '',
                'Total Licenses': '',
                'Total License Cost': '',
                'Licenses Used': '',
                'License POC': '',
                'License Renewal Date': '',
                'License Expiration Date': '',
                'Approval Status': '',
                'Approval Date': '',
                'Release Date': '',
                'Maintenance Date': '',
                'Retirement Date': '',
                'End of Life/Support Date': '',
                'Extended End of Life/Support Date': '',
                'Critical Information System Asset?': '',
                'Location': '',
                'Purpose': ''
            })


        report = sorted(report, key=lambda s: (s['Software Name'].lower().strip(), s['Version']))
        
        #<----Page Header Start---->#
         
        green_header = self.workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        worksheet.merge_range(0, 0, 0, 20, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            worksheet.write(1, col, '', gray_header_cells)
        worksheet.merge_range(1, 13, 1, 20, '', gray_header_merged) 
        
        worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        worksheet.write(2, 6, 'Office / Org:', gray_label)
        worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            worksheet.write(2, col, '', gray_header_cells)
        worksheet.merge_range(2, 13, 2, 20, '', gray_header_merged) 
        
        worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        worksheet.write(3, 6, 'POC Name:', gray_label)
        worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        worksheet.write(3, 12, '', gray_header_cells)
        worksheet.merge_range(3, 13, 3, 20, '', gray_header_merged) 
        
        worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        worksheet.write(4, 6, 'POC Phone:', gray_label)
        worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        worksheet.write(4, 12, '', gray_header_cells)
        worksheet.merge_range(4, 13, 4, 20, '', gray_header_merged) 
        
        worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            worksheet.write(5, col, '', gray_header_cells)
        worksheet.merge_range(5, 13, 5, 20, '', gray_header_merged) 
        
        #<----Page Header End---->#
        
        row = 6
        bold = self.workbook.add_format({'font_size':12, 'bold': True, 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        wrap_text = self.workbook.add_format({'font_size':11, 'text_wrap': True, 'border': 1})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
                
        # Dropdown Logic
                
        if "Yes No" in self.defined_names:
            yes_no_columns = {
                31: 'In response to CP-2(8).1, please select Yes or No to annotate wheather or not this software is Critical Information System Asset.'
            }
            
            for col, tooltip in yes_no_columns.items():
                for r in range(7, row):
                    worksheet.data_validation(r, col, r, col, {
                        'validate': 'list',
                        'source': f'={self.defined_names["Yes No"]}',
                        'input_message': tooltip,
                        'show_input': True,
                        'show_error': True
                    }) 
        
        if "Software Type" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 1, r, 1, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Software Type"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
                
        if "Approval" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 24, r, 24, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Approval"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })

    def rpt_asset_traceability(self):
        """Generates the Asset Traceability list"""
        #TODO Not matching ckl and nessus inputs
        if 'rpt_asset_traceability' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building Asset Traceability Tab')

        worksheet = self.workbook.add_worksheet('Asset Traceability')
        worksheet.activate()
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Asset Traceability' Tab")

        widths = [
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25
            ]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        hardware = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                filename: filename,
                version: version,
                feed: feed,
                policy: policy,
                scan_date: scan_date,
                
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os:os,
                    port_range: port_range,
                    scan_user: scan_user,
                    credentialed: credentialed,
                    scan_details: requirements[?plugin_id == `19506`] | [0].comments
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                if Utils.is_ip(str(host['hostname'])):
                    fqdn_val = (str(host['hostname']))
                elif '.' in str(host['hostname']):
                    fqdn_val = (str(host['hostname']).split('.')[0])
                else:
                    fqdn_val = (str(host['hostname']))
                    
                scan_date = datetime.datetime.strptime(scan['scan_date'], '%a %b %d %H:%M:%S %Y')
                if scan['feed']:
                    feed = datetime.datetime.strptime(scan['feed'], '%Y%m%d%H%M')
                else:
                    feed = ''
                
                if host['scan_details']:
                    for line in host['scan_details'].split('\n'):
                        if 'Plugin feed version' in line:
                            k,v = line.split(':', 1)
                            try:
                                feed = datetime.datetime.strptime(str(v).strip(), '%Y%m%d%H%M')
                            except:
                                pass
                                
                        if 'Scan Start Date' in line:
                            k,v = line.split(':', 1)
                            try:
                                scan_date = datetime.datetime.strptime( str(v).strip() , '%Y/%m/%d %H:%M %Z')
                            except:
                                pass
                        
                # print(scan_date, feed)

                hardware.append({
                    'Asset Name'                : fqdn_val,
                    'IP'                                     : host['ip'],
                    'OS'                                     : host['os'],

                    'ACAS Scan Files'                        : os.path.basename(scan['filename']),
                    'ACAS Scanner Versions'                  : scan['version'],
                    'ACAS Scan Policy'                       : scan['policy'],
                    'ACAS Port Range 0-65535'                : 'True' if str(host['port_range']).strip() == '0-65535' or str(host['port_range']).strip() == 'all ports' else 'False',
                    'ACAS Scan Users'                        : host['scan_user'],
                    'ACAS Credentialed Checks'               : host['credentialed'],
                    
                    'ACAS Feed Version'                      : feed.strftime('%Y%m%d%H%M') if feed else '',
                    'ACAS Scan Start Date'                   : scan_date.strftime('%Y/%m/%d %H:%M %Z'),
                    'ACAS Days Between Plugin Feed And Scan' : (scan_date - feed).days if feed and scan_date else '',
                    
                    'STIG CKL File'                      : '',
                    'STIG CKL Version/Release'               : '',
                    'STIG CKL Blank Comments/Findings'       : '',
                    'STIG CKL Total Not Reviewed'            : '',

                    'SCAP Benchmark File'                    : '',
                    'SCAP Scanner Versions'                  : '',
                    'SCAP Benchmark Version/Release'         : '',
                    'SCAP Benchmark Policy'                  : '',
                    'SCAP Scan Users'                        : '',
                    'SCAP Credentialed Checks'               : '',
                    'SCAP Benchmark Errors'                  : '',
                })

        scap_scans = jmespath.search(
            """results[?type=='SCAP'].{
                filename: filename,
                version: version,
                release: release,
                policy: policy,
                scan_date: scan_date,
                scanner_edition: scanner_edition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scan_user,
                credentialed: credentialed,
                error: requirements[]  | [?status == 'E'].[comments, severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in scap_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            hardware.append({
                'Asset Name'                : fqdn_val,
                'IP'                                     : scan['ip'],
                'OS'                                     : scan['os'],

                'ACAS Scan Files'                        : '',
                'ACAS Scanner Versions'                  : '',
                'ACAS Scan Policy'                       : '',
                'ACAS Port Range 0-65535'                : '',
                'ACAS Scan Users'                        : '',
                'ACAS Credentialed Checks'               : '',
                'ACAS Feed Version'                      : '',
                'ACAS Scan Start Date'                   : '',
                'ACAS Days Between Plugin Feed And Scan' : '',

                'STIG CKL File'                          : '',
                'STIG CKL Version/Release'               : '',
                'STIG CKL Blank Comments/Findings'       : '',
                'STIG CKL Total Not Reviewed'            : '',

                'SCAP Benchmark File'                    : os.path.basename(scan['filename']),
                'SCAP Scanner Versions'                  : scan['scanner_edition'],
                'SCAP Benchmark Version/Release'         : f"V{scan['version']}R{scan['release']}",
                'SCAP Benchmark Policy'                  : scan['policy'],
                'SCAP Scan Users'                        : scan['scan_user'],
                'SCAP Credentialed Checks'               : scan['credentialed'],
                'SCAP Benchmark Errors'                  : len(scan['error'])
            })

        ckl_scans = jmespath.search(
            """results[?type=='CKL'].{
                filename: filename,
                version: version,
                release: release,
                policy: policy,
                scan_date: scan_date,
                scanner_edition: scanner_edition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scan_user,
                credentialed: credentialed,
                blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && finding_details == '')].[comments, severity, status],
                not_reviewed: requirements[]  | [?status == 'NR'].[comments, severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in ckl_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            hardware.append({
                'Asset Name'                : fqdn_val,
                'IP'                                     : scan['ip'],
                'OS'                                     : scan['os'],

                'ACAS Scan Files'                        : '',
                'ACAS Scanner Versions'                  : '',
                'ACAS Scan Policy'                       : '',
                'ACAS Port Range 0-65535'                : '',
                'ACAS Scan Users'                        : '',
                'ACAS Credentialed Checks'               : '',
                'ACAS Feed Version'                      : '',
                'ACAS Scan Start Date'                   : '',
                'ACAS Days Between Plugin Feed And Scan' : '',

                'STIG CKL File'                          : os.path.basename(scan['filename']),
                'STIG CKL Version/Release'               : f"V{scan['version']}R{scan['release']}",
                'STIG CKL Blank Comments/Findings'       : len(scan['blank_comments']),
                'STIG CKL Total Not Reviewed'            : len(scan['not_reviewed']),

                'SCAP Benchmark File'                    : '',
                'SCAP Scanner Versions'                  : '',
                'SCAP Benchmark Version/Release'         : '',
                'SCAP Benchmark Policy'                  : '',
                'SCAP Scan Users'                        : '',
                'SCAP Credentialed Checks'               : '',
                'SCAP Benchmark Errors'                  : '',
            })

        hardware = sorted(hardware, key=lambda hardware: hardware['Asset Name'])
        hardware_count = 0

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if hardware:
            col = 0
            for column_header in hardware[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in hardware:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_hardware(self):
        """Generates the hardware list"""
        if 'rpt_hardware' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Hardware Tab')

        # Creates the hardware tab

        worksheet = self.workbook.add_worksheet('Hardware')
        self.generated_sheets.append('Hardware')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Hardware' Tab")

        widths = [45, 31, 32, 28, 28, 29, 27, 34, 33, 32, 33, 46, 40, 40, 39, 36, 37, 44, 23, 44, 43]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        # Creates filter for results on row 7

        worksheet.autofilter(6, 0, 6, int(len(widths))-1)
        
        # Define result sets
        
        hardware = []
        hosts = []
        
        # Load data from .pkl of scan results
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
           
        # Aquire results from parseNessus function in scan_parser.py out of scan pickle
           
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].hosts[] | [*].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os, mac: mac  }",
            { 'results' : scan_results}
        )
        
        for host in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(host['hostname'])):
                fqdn_val = (str(host['hostname']))
            elif '.' in str(host['hostname']):
                fqdn_val = (str(host['hostname']).split('.')[0])
            else:
                fqdn_val = (str(host['hostname']))

            # Defines header names and links to variables for result input

            if fqdn_val not in hosts:
                hosts.append(fqdn_val)
                hardware.append({
                    '#'                                  : '',
                    'Component Type'                     : host['device_type'],
                    'Asset Name'                         : fqdn_val,
                    'Nickname'                           : '',
                    'MAC Address'                        : host['mac'],
                    'Asset IP Address'                   : host['ip'],
                    'Public Facing'                      : 'No',
                    'Public Facing FQDN'                 : '',
                    'Public Facing IP Address'           : '',
                    'Public Facing URL(s)'               : '',
                    'Virtual Asset?'                     : '',
                    'Manufacturer'                       : host['manufacturer'],
                    'Model Number'                       : host['model'],
                    'Serial Number'                      : host['serial'],
                    'Line Item Number'                   : '',
                    'National Stock Number'              : '',
                    'OS/iOS/FW Version'                  : host['os'],
                    'Memory Size / Type'                 : '',
                    'Location (P/C/S & Building)'        : '',
                    'Approval Status'                    : '',
                    'Critical Information System Asset?' : ''
                })
        
        # Aquire results from parseSCAP function in scan_parser.py out of scan pickle
        
        scap_scans = jmespath.search(
            "results[?type=='SCAP' || type == 'CKL'].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os, mac: mac  }",
            { 'results' : scan_results}
        )
        
        for scan in scap_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            # Defines header names and links to variables for result input

            if fqdn_val not in hosts:
                hosts.append(fqdn_val)
                hardware.append({
                    '#'                                  : '',
                    'Component Type'                     : scan['device_type'] if 'device_type' in scan and scan['device_type'].strip() != '' else 'Unknown',
                    'Asset Name'                         : fqdn_val,
                    'Nickname'                           : '',
                    'MAC Address'                        : scan['mac'],
                    'Asset IP Address'                   : scan['ip'],
                    'Public Facing'                      : 'No',
                    'Public Facing FQDN'                 : '',
                    'Public Facing IP Address'           : '',
                    'Public Facing URL(s)'               : '',
                    'Virtual Asset?'                     : '',
                    'Manufacturer'                       : scan['manufacturer'],
                    'Model Number'                       : scan['model'],
                    'Serial Number'                      : scan['serial'],
                    'Line Item Number'                   : '',
                    'National Stock Number'              : '',
                    'OS/iOS/FW Version'                  : scan['os'],
                    'Memory Size / Type'                 : '',
                    'Location (P/C/S & Building)'        : '',
                    'Approval Status'                    : '',
                    'Critical Information System Asset?' : ''
                })
        
        hardware = sorted(hardware, key=lambda hardware: hardware['Asset Name'])
        
        # Commented out per HW/SW instructions - No data in # column
        
        # hardware_count = 0
        # for asset in hardware:
            # hardware_count += 1
            # asset['#'] = hardware_count
         
        #<----Page Header Start---->#
         
        green_header = self.workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        worksheet.merge_range(0, 0, 0, 20, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            worksheet.write(1, col, '', gray_header_cells)
        worksheet.merge_range(1, 13, 1, 20, '', gray_header_merged) 
        
        worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        worksheet.write(2, 6, 'Office / Org:', gray_label)
        worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            worksheet.write(2, col, '', gray_header_cells)
        worksheet.merge_range(2, 13, 2, 20, '', gray_header_merged) 
        
        worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        worksheet.write(3, 6, 'POC Name:', gray_label)
        worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        worksheet.write(3, 12, '', gray_header_cells)
        worksheet.merge_range(3, 13, 3, 20, '', gray_header_merged) 
        
        worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        worksheet.write(4, 6, 'POC Phone:', gray_label)
        worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        worksheet.write(4, 12, '', gray_header_cells)
        worksheet.merge_range(4, 13, 4, 20, '', gray_header_merged) 
        
        worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            worksheet.write(5, col, '', gray_header_cells)
        worksheet.merge_range(5, 13, 5, 20, '', gray_header_merged) 
        
        #<----Page Header End---->#
        
        # Data writing from SCAP/ACAS results
        
        row = 6
        bold = self.workbook.add_format({'font_size':12, 'bold': True, 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        wrap_text = self.workbook.add_format({'font_size':11, 'text_wrap': True, 'border': 1})

        if hardware:
            col = 0
            for column_header in hardware[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in hardware:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
        
        # Dropdown Logic
                
        if "Yes No" in self.defined_names:
            yes_no_columns = {
                6: '',
                10: "This column indiciates if the asset is a virtual machine. If 'Yes' is selected, the Manufacturer, Model Number, and Serial Number columns should reflect, 'Virtual'.",
                20: 'In response to CP-2(8).1, please select Yes or No to annotate wheather or not this software is Critical Information System Asset.'
            }
            
            for col, tooltip in yes_no_columns.items():
                for r in range(7, row):
                    worksheet.data_validation(r, col, r, col, {
                        'validate': 'list',
                        'source': f'={self.defined_names["Yes No"]}',
                        'input_message': tooltip,
                        'show_input': True,
                        'show_error': True
                    })                
                
        if "Hardware Type" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 1, r, 1, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Hardware Type"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
                
        if "Approval" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 19, r, 19, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Approval"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
  
    def rpt_ppsm(self):
        """ Generates PPSM Report """
        if 'rpt_ppsm' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building PPSM Tab')
        worksheet = self.workbook.add_worksheet('PPSM')
        self.generated_sheets.append('PPSM')
        
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'PPSM' Tab")

        widths = [30, 30, 30, 30, 30]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
        
        self.service_map = (
            self.scar_data
                .get("data_mapping", {})
                .get("common_services", {})
        )
        
        # Load dynamic plugin list
        dynamic_plugin_path = os.path.join(self.scar_conf.get('application_path'), "data", "dynamic_plugins.json")
        try:
            with open(dynamic_plugin_path, "r") as f:
                service_plugins = set(json.load(f))
            if not service_plugins:
                service_plugins = {11219}
                logging.warning("[PPSM] dynamic_plugins.json is empty, falling back to 11219")
            else:
                logging.info(f"[PPSM] Loaded {len(service_plugins)} dynamic plugins")
        except Exception as e:
            service_plugins = set()
            logging.warning(f"[PPSM] Could not load dynamic_plugins.json: {e}")
        
        # logging.debug(f"[PPSM] 1st five Keys in service map {list(self.service_map.keys())[:5]}")
            
        worksheet.autofilter(6, 0, 6, int(len(widths))-1)

        ports = []
        
        for result in scan_results:
            if result.get("type") != "ACAS":
                continue
            for host in result.get("hosts", []):
                for req in host.get("requirements", []):
                    if req.get("plugin_id") in service_plugins:
                        port = str(req.get("port")).strip()
                        proto = req.get("protocol", "").strip().lower()
                        key = f"{port}/{proto}"
                        service = self.service_map.get(key)
                        if service is None:
                            service = req.get("service", "")
                            # logging.debug(f"[PPSM] No service match for {key} (using plugin service)")
                        service = service.rstrip("?")
                        if not service or service.lower() == "unknown":
                            service = ""
                        else:
                            service = service.upper()
                        row = {
                            "Port": port,
                            "Originating IP Address": "",
                            "Destination IP Address": host.get("ip", ""),
                            "Protocol": proto,
                            "Service": service
                        }
                        ports.append(row)

                # Add netstat-derived entries
                for conn in host.get("netstat", []):
                    proto = (conn.get("proto") or "").strip().lower()
                    port = str(conn.get("dest_port")).strip()
                    row = {
                        "Port": port,
                        "Originating IP Address": conn.get("origin_ip"),
                        "Destination IP Address": conn.get("dest_ip"),
                        "Protocol": proto,
                        "Service": ""
                    }
                    if not row["Service"]:
                        key = f"{port}/{proto}"
                        # logging.debug(f"[PPSM] Built Key: '{key}' -- In map: {key in self.service_map}")
                        if key not in self.service_map:
                            # logging.debug(f"[PPSM] No service match for {key}")
                            pass
                        row["Service"] = self.service_map.get(key, "")
                    ports.append(row)

        row = 6
        bold = self.workbook.add_format({'bold': True, 'font_size': 12, 'border': 1})
        wrap_text = self.workbook.add_format({'font_size': 12, 'text_wrap': True, 'border': 1})

        worksheet.write(row, 0, "Port", bold)
        worksheet.write(row, 1, "Originating IP Address", bold)
        worksheet.write(row, 2, "Destination IP Address", bold)
        worksheet.write(row, 3, "Protocol", bold)
        worksheet.write(row, 4, "Service", bold)
        row += 1

        for row_data in ports:
            worksheet.write(row, 0, row_data["Port"], wrap_text)
            worksheet.write(row, 1, row_data["Originating IP Address"], wrap_text)
            worksheet.write(row, 2, row_data["Destination IP Address"], wrap_text)
            worksheet.write(row, 3, row_data["Protocol"], wrap_text)
            row += 1
  
    def rpt_cci(self):
        """ Generates CCI Report """
        if 'rpt_cci' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building CCI Tab')
        worksheet = self.workbook.add_worksheet('CCI Data')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'CCI Data' Tab")

        widths = [25, 25, 25, 25, 25, 25, 125, 125]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        ccis = []

        for cci in self.scar_data.get('data_mapping')['rmf_cci']:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            ccis.append({
                'Control' : cci['control'],
                'Title' : cci['title'],
                'Family' : cci['subject_area'],
                'Impact' : cci['impact'],
                'Priority' : cci['priority'],
                'CCI' : cci['cci'],
                'Definition' : cci['definition'],
                'Description' : cci['description'],
            })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if ccis:
            col = 0
            for column_header in ccis[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in ccis:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_acas_uniq_vuln(self):
        """ Generates ACAS Unique Vuln tab """
        if 'rpt_acas_uniq_vuln' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building ACAS Unique Vuln Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique Vuln')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'ACAS Unique Vuln' Tab")

        widths = [25, 75, 50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [?severity != `0`].{ 
                        plugin_id: plugin_id,
                        title: req_title,
                        grp_id: grp_id,
                        severity: severity
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
                    QtGui.QGuiApplication.processEvents()
                    
                for req in host['requirements']:
                    if not list(filter(lambda x: x['plugin_id'] == req['plugin_id'], plugins)):
                        plugins.append(req)
                    if int(req['plugin_id']) not in plugin_count:
                        plugin_count[int(req['plugin_id'])] = 1
                    else:
                        plugin_count[int(req['plugin_id'])] += 1
                    
        plugins = sorted(plugins, key=lambda plugin: plugin['plugin_id'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin'         : plugin['plugin_id'],
                'Plugin Name'    : plugin['title'],
                'Family'         : plugin['grp_id'],
                'Raw Severity'   : Utils.risk_val(plugin['severity'], 'CAT'),
                'Total'          : plugin_count[int(plugin['plugin_id'])]
            })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if plugins_rpt:
            col = 0
            for column_header in plugins_rpt[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in plugins_rpt:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_acas_uniq_iavm(self):
        """ Generates ACAS Unique IAVM Tab """
        if 'rpt_acas_uniq_iavm' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building ACAS Unique IAVM Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique IAVM')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'ACAS Unique IAVM' Tab")

        widths = [25, 25, 50, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [?iavm != '' && severity != `0`].{ 
                        plugin_id: plugin_id,
                        iavm: iavm,
                        title: req_title,
                        grp_id: grp_id,
                        severity: severity
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
                    QtGui.QGuiApplication.processEvents()
                    
                for req in host['requirements']:
                    if not list(filter(lambda x: x['plugin_id'] == req['plugin_id'], plugins)):
                        plugins.append(req)
                    if int(req['plugin_id']) not in plugin_count:
                        plugin_count[int(req['plugin_id'])] = 1
                    else:
                        plugin_count[int(req['plugin_id'])] += 1
                    
        plugins = sorted(plugins, key=lambda plugin: plugin['plugin_id'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin'     : plugin['plugin_id'],
                'IAVM'       : plugin['iavm'],
                'Plugin Name': plugin['title'],
                'Family'     : plugin['grp_id'],
                'Severity'   : Utils.risk_val(plugin['severity'], 'CAT'),
                'Total'      : plugin_count[int(plugin['plugin_id'])]
            })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if plugins_rpt:
            col = 0
            for column_header in plugins_rpt[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in plugins_rpt:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_missing_patches(self):
        """ Generates Missing Patches tab """
        if 'rpt_missing_patches' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Missing Patches tab')
        worksheet = self.workbook.add_worksheet('Missing Patches')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Missing Patches' Tab")

        widths = [35, 50, 50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        patches = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,

                    requirements: requirements[]  | [?plugin_id == `66334`].{ comments: comments}
                }
            }""",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                for req in host['requirements']:
                    for patch in re.findall(r'\+ Action to take : (.+)+', req['comments']):
                        patches.append({
                            'Hostname': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })
                    for patch in re.findall(r'- (.+)+', req['comments']):
                        patches.append({
                            'Hostname': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })

        patches = sorted(
            patches,
            key=lambda s: (str(s['Hostname']).lower().strip(), str(s['Action']).lower().strip())
        )
        
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if patches:
            col = 0
            for column_header in patches[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in patches:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_summary(self):
        """ Generates Scan Summary Tab """
        if 'rpt_summary' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Summary Tab')
        worksheet = self.workbook.add_worksheet('Summary')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Summary' Tab")

        widths = [
            10,30,20,50,100,
            20,20,20,20,20,
            50,50,20,25,
            10,10,10,10,10,10
        ]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        summary_results = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
        disa_scans = jmespath.search(
            """results[?type=='CKL' || type=='SCAP'].{
                type: type,
                
                hostname: hostname,
                ip: ip,
                os: os,
                
                filename: filename,
                scan_date: scan_date,
                duration: duration,
                
                version: version,
                release: release,
                policy: policy,
                
                
                credentialed: credentialed
                scan_user: scan_user,
                
                cati: requirements[]   | [?status != 'C' && severity > `2`].[severity, status],
                catii: requirements[]  | [?status != 'C' && severity == `2`].[severity, status],
                catiii: requirements[] | [?status != 'C' && severity == `1`].[severity, status],
                cativ: requirements[]  | [?status != 'C' && severity == `0`].[severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in disa_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            duration = ''
            if str(scan['duration']).strip() != '':
                duration = str(reduce(lambda x, y: x*60+y, [int(i) for i in (str(scan['duration'])).split(':')])) + ' sec'
            
            summary_results.append({
                'Type': scan['type'],
                
                'Hostname': scan['hostname'],
                'IP': scan['ip'],
                'OS': scan['os'],
                
                'Scan File Name': os.path.basename(scan['filename']),
                'Scan Date': scan['scan_date'],
                'Scan Duration': duration,
                'Scan To Feed Difference': '',
                'Version': scan['version'],
                'Release': scan['release'],
                'Scan Policy': scan['policy'],
                'Port Range': '',
                
                'Credentialed': scan['credentialed'],
                'Scan User': scan['scan_user'],

                'CAT I': len(scan['cati']),
                'CAT II': len(scan['catii']),
                'CAT III': len(scan['catiii']),
                'CAT IV': len(scan['cativ']),
                'Total': len(scan['cati']) + len(scan['catii']) + len(scan['catiii']) + len(scan['cativ']),
                'Score': 10*len(scan['cati']) + 3*len(scan['catii']) + len(scan['catiii']),
            })

        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                type: type,
                filename: filename,
                scan_date: scan_date,
                version: version,
                feed: feed,
                policy: policy,
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,
                    credentialed: credentialed,
                    scan_user: scan_user,
                    duration: duration,
                    port_range: port_range,
                    
                    cati:   requirements[] | [?status != 'C' && severity > `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catii:  requirements[] | [?status != 'C' && severity == `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catiii: requirements[] | [?status != 'C' && severity == `1`].{ plugin_id: plugin_id, severity: severity, status: status},
                    cativ:  requirements[] | [?status != 'C' && severity == `0`].{ plugin_id: plugin_id, severity: severity, status: status}
                }
            }""",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                summary_results.append({
                    'Type': scan['type'],
                    
                    'Hostname': host['hostname'],
                    'IP': host['ip'],
                    'OS': host['os'],
                    
                    'Scan File Name': os.path.basename(scan['filename']),
                    'Scan Date': scan['scan_date'],
                    'Scan Duration': host['duration'],
                    'Scan To Feed Difference': (
                                datetime.datetime.strptime(scan['scan_date'], '%a %b %d %H:%M:%S %Y') -
                                datetime.datetime.strptime(scan['feed'], '%Y%m%d%H%M')
                            ).days if scan['scan_date'] and scan['feed'] else '',
                            
                    'Version': scan['version'],
                    'Release': scan['feed'],
                    'Scan Policy': scan['policy'],
                    'Port Range': host['port_range'],

                    'Credentialed': host['credentialed'],
                    'Scan User': host['scan_user'],

                    'CAT I': len(host['cati']),
                    'CAT II': len(host['catii']),
                    'CAT III': len(host['catiii']),
                    'CAT IV': len(host['cativ']),
                    'Total': len(host['cati']) + len(host['catii']) + len(host['catiii']) + len(host['cativ']),
                    'Score': 10*len(host['cati']) + 3*len(host['catii']) + len(host['catiii']),
                    
                })

        summary_results = sorted(
            summary_results,
            key=lambda s: (str(s['Type']).lower().strip(), str(s['Hostname']).lower().strip())
        )
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if summary_results:
            col = 0
            for k in summary_results[0]:
                worksheet.write(row, col, k, bold)
                col += 1
            row += 1

            for result in summary_results:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_raw_data(self):
        """ Generates RAW Data Tab """
        if 'rpt_raw_data' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Raw Data Tab')
        worksheet = self.workbook.add_worksheet('Raw Data')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Raw Data' Tab")

        worksheet.set_column('A:A', 15)
        worksheet.set_column('B:B', 40)
        worksheet.set_column('C:C', 40)
        worksheet.set_column('D:D', 30)
        worksheet.set_column('E:E', 10)
        worksheet.set_column('F:F', 15)
        worksheet.set_column('G:G', 10)
        worksheet.set_column('H:H', 10)

        worksheet.set_column('I:I', 15)
        worksheet.set_column('J:J', 45)
        worksheet.set_column('K:K', 30)
        worksheet.set_column('L:L', 25)
        worksheet.set_column('M:M', 25)
        worksheet.set_column('N:N', 15)
        worksheet.set_column('O:O', 20)
        worksheet.set_column('P:P', 20)
        worksheet.set_column('Q:Q', 20)
        worksheet.set_column('R:R', 20)
        worksheet.set_column('S:S', 75)
        worksheet.set_column('T:T', 15)
        worksheet.set_column('U:U', 15)
        worksheet.set_column('V:V', 75)
        worksheet.set_column('W:W', 75)
        worksheet.set_column('X:X', 75)
        worksheet.set_column('Y:Y', 25)
        worksheet.set_column('Z:Z', 20)
        worksheet.set_column('AA:AA', 25)
        worksheet.set_column('AB:AB', 75)
        worksheet.autofilter(0, 0, 0, 27)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        raw_results = []
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ type: type, title: title, filename: filename, scan_date: scan_date, version: version, feed: feed, hosts: hosts[] | [*].{ hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ publication_date: publication_date, modification_date : modification_date, comments: comments, grp_id: grp_id, plugin_id: plugin_id, req_title: req_title, severity: severity, status: status, finding_details: finding_details, description: description, solution: solution, fix_id: fix_id, references: references, resources: resources } } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:

                    raw_results.append({
                            'Scan Type'         : scan['type'].upper(),
                            'Scan Title'        : scan['title'],
                            'Filename'          : os.path.basename(scan['filename']),
                            'Scan Date'         : scan['scan_date'],
                            'Version'           : scan['version'],
                            'Release'           : scan['feed'],

                            'Publication Date'  : req['publication_date'],
                            'Modification Date' : req['modification_date'],
                            'Credentialed'      : host['credentialed'],
                            'Hostname'          : host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'grp_id'             : req['grp_id'],
                            'vuln_id'            : '',
                            'rule_id'            : '',
                            'plugin_id'          : req['plugin_id'],
                            'IA Controls'       : '',
                            'RMF Controls'      : '',
                            'Assessments'       : '',
                            'CCI'               : '',
                            'Title'             : req['req_title'],
                            'Severity'          : Utils.risk_val(str(req['severity']), 'CAT'),
                            'Status'            : Utils.status(req['status'], 'HUMAN'),
                            'Finding Details'   : req['finding_details'][0:32760],
                            'Description'       : req['description'][0:32760],
                            'Solution'          : req['solution'][0:32760],
                            'fix_id'             : req['fix_id'],
                            'References'        : req['references'][0:32760],
                            'Resources'         : req['resources'],
                            'Comments'          : '',
                        })

        disa_scans = jmespath.search(
            "results[?type=='CKL' || type=='SCAP'].{ type: type, filename: filename, scan_date: scan_date, hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ comments: comments, grp_id: grp_id, plugin_id: plugin_id, req_title: req_title, severity: severity, status: status, finding_details: finding_details, description: description, solution: solution, fix_id: fix_id, references: references, resources: resources, cci: cci, assessments: assessments, rmf_controls: rmf_controls, ia_controls: ia_controls, rule_id: rule_id, vuln_id: vuln_id, version: version, release: release, stig_id: stigid, stig_uuid: uuid, stig_classification: classification, scan_title: title } }",
            { 'results' : scan_results}
        )

        for scan in disa_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for req in scan['requirements']:
                raw_results.append({
                        'Scan Type'         : scan['type'].upper(),
                        'Scan Title'        : req['scan_title'].replace(self.strings['STIG'], ''),
                        'Filename'          : os.path.basename(scan['filename']),
                        'Scan Date'         : scan['scan_date'],
                        'Version'           : int(req['version'].strip(string.ascii_letters)),
                        'Release'           : int(req['release'].strip(string.ascii_letters)),
                        'Publication Date'  : '',
                        'Modification Date' : '',
                        'Credentialed'      : scan['credentialed'],
                        'Hostname'          : scan['hostname'] if scan['hostname'].strip() != '' else scan['ip'],
                        'grp_id'             : req['grp_id'],
                        'vuln_id'            : req['vuln_id'],
                        'rule_id'            : req['rule_id'],
                        'plugin_id'          : req['plugin_id'],
                        'IA Controls'       : req['ia_controls'],
                        'RMF Controls'      : req['rmf_controls'],
                        'Assessments'       : req['assessments'],
                        'CCI'               : req['cci'],
                        'Title'             : req['req_title'],
                        'Severity'          : Utils.risk_val(str(req['severity']), 'CAT'),
                        'Status'            : Utils.status(req['status'], 'HUMAN'),
                        'Finding Details'   : req['finding_details'][0:32760],
                        'Description'       : req['description'][0:32760],
                        'Solution'          : req['solution'][0:32760],
                        'fix_id'             : req['fix_id'],
                        'References'        : req['references'][0:32760],
                        'Resources'         : req['resources'],
                        'Comments'          : req['comments'][0:32760],
                    })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if raw_results:
            col = 0
            for column_header in raw_results[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in raw_results:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_operating_systems(self):
        """ Generates OS Tab """
        if 'rpt_operating_systems' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building OS Tab')
        worksheet = self.workbook.add_worksheet('Operating Systems')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Operating Systems' Tab")

        widths = [50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        os_list = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
            
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ os: os } }",
            { 'results' : scan_results}
        )
        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                if not any(host['os'] in x['os'] for x in os_list):
                    os_list.append({
                        'os': host['os'],
                        'count': 1,
                        'method': 'Active',
                    })
                else:
                    for operating_system in os_list:
                        if operating_system['os'] == host['os']:
                            operating_system['count'] += 1


        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})
        if os_list:
            os_list = sorted(os_list, key=lambda k: k['os'])
            row = 1
            bold = self.workbook.add_format({'bold': True})
            worksheet.write(0, 0, 'Operating System', bold)
            worksheet.write(0, 1, 'Count', bold)
            worksheet.write(0, 2, 'Detection Method', bold)
            for result in os_list:
                worksheet.write(row, 0, result['os'], wrap_text)
                worksheet.write(row, 1, result['count'], wrap_text)
                worksheet.write(row, 2, result['method'], wrap_text)
                row += 1

    def rpt_local_users(self):
        """ Generates Local Users tab """
        if 'rpt_local_users' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Local Users Tab')
        worksheet = self.workbook.add_worksheet('Local Users')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Local Users' Tab")

        widths = [50,50,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        users = []
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `10860`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'- ([_a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })


        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `126527`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'- ([_a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })


        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `95928`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'User\s+:\s+([a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })

        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})
        users = sorted(users, key=lambda k: k['Host'])
        if users:
            row = 1
            bold = self.workbook.add_format({'bold': True})
            worksheet.write(0, 0, 'Host', bold)
            worksheet.write(0, 1, 'Operating System', bold)
            worksheet.write(0, 2, 'User', bold)
            for result in users:
                worksheet.write(row, 0, result['Host'], wrap_text)
                worksheet.write(row, 1, result['OS'], wrap_text)
                worksheet.write(row, 2, result['User'], wrap_text)
                row += 1

    def rpt_deviations(self):
        """Generates Deviations report from CKL/CKLB comments only"""
        if 'rpt_deviations' in self.scar_conf.get('skip_reports'):
            return None

        logging.info('Building Deviations Tab')
        worksheet = self.workbook.add_worksheet('Deviations')
        self.generated_sheets.append('Deviations')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Deviations' Tab")
            QtGui.QGuiApplication.processEvents()

        # Reuse POA&M-like column sizing 
        widths = [1,20,40,15,25,25,45,25,25,60,30,25,75,40]
        ascii_letters = string.ascii_uppercase
        for idx, w in enumerate(widths):
            # Support going beyond column Z
            worksheet.set_column(f"{xl_col_to_name(idx)}:{xl_col_to_name(idx)}", w)

        # Match POA&M’s “header starts at row 6” look-and-feel
        worksheet.autofilter(6, 0, 6, len(widths) - 1)

        # Load parsed scans
        import pickle, os
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)

        # Only CKL/CKLB checklists
        disa_ckls = jmespath.search(
            """results[?type=='CKL' || type=='CKLB'].{
                filename: filename,
                version: version,
                release: release,
                hostname: hostname,

                requirements: requirements[] | [*].{
                    scan_title: title,
                    req_title: req_title,
                    cci: cci,
                    grp_id: grp_id,
                    vuln_id: vuln_id,
                    rule_id: rule_id,
                    plugin_id: plugin_id,
                    status: status,
                    finding_details: finding_details,
                    comments: comments,
                    severity: severity,
                    description: description,
                    solution: solution
                }
            }""",
            {'results': scan_results}
        ) or []
        
        selected_mitigations = {}
        for mit in self.scar_data.get('mitigations', {}).get('mitigations', []):
            if mit.get('plugin_id', '').strip():
                selected_mitigations[str(mit['plugin_id'])] = mit['mitigation']
            if mit.get('vuln_id', '').strip():
                selected_mitigations[str(mit['vuln_id'])] = mit['mitigation']
            if mit.get('rule_id', '').strip():
                selected_mitigations[str(mit['rule_id'])] = mit['mitigation']

        # Regex for the deviation line inside "Rule Result"
        # Example: "Rule Result     : Pass [Deviation authorized by 'ISS IT' at 2025-08-11T11:29:26 Reason: 'Bitlocker pin not required.']"
        dev_re = re.compile(
            r"Deviation authorized by '([^']+)' at ([0-9T:\-]+)\s+Reason:\s*'([^']+)'",
            re.IGNORECASE
        )

        report_rows = []
        for scan in disa_ckls:
            host = scan.get('hostname', '')


            for req in (scan.get('requirements') or []):
                comments = (req.get('comments') or "").strip()
                if not comments:
                    continue
                scan_title = req.get('scan_title', '')

                # Find the "Rule Result" line(s) and extract deviation info
                # We search entire comment blob to be resilient to formatting.
                m = dev_re.search(comments)
                if not m:
                    continue  # Only include entries that actually have a logged deviation

                auth_by, ts, reason = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

                # Derive RMF control like POA&M does (preferring req['rmf_controls'] if present elsewhere)
                rmf_controls = req.get('rmf_controls', '') or \
                    self.scar_data.get('data_mapping', {}).get('ap_mapping', {}).get(req.get('cci', ''), '')

                status_h = Utils.status(req.get('status', ''), 'HUMAN') if req.get('status') else 'Status Unknown'
                sev_num = req.get('severity', '')
                sev_poam = Utils.risk_val(sev_num, 'POAM') if sev_num != '' else ''
                sev_min = Utils.risk_val(sev_num, 'MIN') if sev_num != '' else ''
                
                mitigation_statement = ''
                if self.scar_conf.get('mitigation_statements') == 'poam':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                elif self.scar_conf.get('mitigation_statements') == 'ckl':
                    mitigation_statement = comments
                elif self.scar_conf.get('mitigation_statements') == 'both':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                    if mitigation_statement.strip() == '':
                        mitigation_statement = comments

                # Build a POA&M-like row (keys ordered to resemble rpt_poam) + deviation fields
                row = {
                    'A'                                                 : '',
                    'Deviation Item ID'                                 : '',
                    'Control Vulnerability Description'                 : f"Title: {req.get('req_title','')}\nFamily: {req.get('grp_id','')}\n\nDescription:\n{req.get('description','')}",
                    'Security Control Number (NC/NA controls only)'     : rmf_controls,
                    'Office/Org'                                        : f"{self.scar_data.get('command')}\n{self.scar_data.get('name')}\n{self.scar_data.get('phone')}\n{self.scar_data.get('email')}\n".strip(),
                    'Security Checks'                                   : f"{req.get('plugin_id','')}{req.get('rule_id','')}\n{req.get('vuln_id','')}",
                    'Source Identifying Control Vulnerability'          : f"CKL {scan_title}",
                    'Deviation Authorized By'                           : auth_by,
                    'Deviation Timestamp'                               : ts,
                    'Deviation Reason'                                  : reason,
                    'Comments'                                          : comments,
                    'Raw Severity'                                      : sev_min,
                    'Devices Affected'                                  : host,
                    'Mitigations'                                       : mitigation_statement,
                    # Deviation-specific fields appended (mirrors POA&M style, new columns at the end)
                }

                report_rows.append(row)

        # Sort similar to POA&M (by Status, Source, Security Checks)
        report_rows.sort(key=lambda r: (
            str(r.get('Status','')).lower().strip(),
            str(r.get('Source Identifying Control Vulnerability','')).lower().strip(),
            str(r.get('Security Checks','')).lower().strip()
        ))

        # Write out
        start_row = 6
        bold = self.workbook.add_format({'bold': True})
        cell_fmt = self.workbook.add_format({'font_size': 8, 'text_wrap': True, 'align': 'left', 'valign': 'top'})

        if report_rows:
            # Header
            for col_idx, header in enumerate(report_rows[0].keys()):
                worksheet.write(start_row, col_idx, header, bold)
            # Rows
            r = start_row + 1
            for entry in report_rows:
                for c, k in enumerate(entry.keys()):
                    worksheet.write(r, c, str(entry[k]).strip(), cell_fmt)
                r += 1
    
    def generate_HWSW_workbook(self):
        """Create HWSW workbook if conditions are met"""
        
        logging.info('Generating HW SW workbook')
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_name = os.path.join(self.report_dir, "HWSW.xlsx")
        self.hwsw_workbook = xlsxwriter.Workbook(summary_name)
        
        # Add hidden lists sheet
        
        summary_dropdown = self.hwsw_workbook.add_worksheet('(U) Lists')
        summary_dropdown.hide()
        if self.dropdown_data:
            col_idx = 0
            for list_name, values in self.dropdown_data.items():
                col_letter = xl_col_to_name(col_idx)
                for row_idx, val in enumerate(values):
                    summary_dropdown.write(row_idx, col_idx, val)
                range_name = f"{list_name.replace(' ', '')}"
                self.hwsw_workbook.define_name(
                    range_name,
                    f'=\'(U) Lists\'!${col_letter}$1:${col_letter}${len(values)}'
                )
                col_idx += 1

        ### Generates the HW Tab
        
        def get_first_mac(mac_field):
            macs = []
            if isinstance(mac_field, list):
                macs = [m.strip() for m in mac_field if m.strip()]
            elif isinstance(mac_field, str):
                normalized = mac_field.replace(',', '\n').replace(';', '\n').replace('\r', '\n').replace(' ', '\n')
                macs = [m.strip() for m in normalized.split('\n') if m.strip()]
            if len(macs) > 1:
                # logging.debug(f"Multiple MACs detected, using first: {macs}")
                logging.info(f"Multiple MACs detected, using first mac")
            return macs[0] if macs else ''
        
        logging.info('Copying hardware data')
        
        if 'rpt_hardware' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Hardware Tab')

        # Creates the hardware tab

        worksheet = self.hwsw_workbook.add_worksheet('Hardware')
        worksheet.activate()
        self.generated_sheets.append('Hardware')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Hardware' Tab")

        widths = [45, 31, 32, 28, 28, 29, 27, 34, 33, 32, 33, 46, 40, 40, 39, 36, 37, 44, 23, 44, 43]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        # Creates filter for results on row 7

        worksheet.autofilter(6, 0, 6, int(len(widths))-1)
        
        # Define result sets
        
        hardware = []
        hosts = []
        host_mac_map = {} # key: (hostname.lower(), mac.upper()), value: index in hardware[]
        ip_only_placeholders = {}
        

        
        # Load data from .pkl of scan results
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
           
        # Aquire results from parseNessus function in scan_parser.py out of scan pickle
           
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].hosts[] | [*].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os, mac: mac  }",
            { 'results' : scan_results}
        )
        
        for host in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            
            hostname = str(host.get('hostname', '')).strip()
            if Utils.is_ip(hostname):
                fqdn_val = hostname
            elif '.' in hostname:
                fqdn_val = hostname.split('.')[0]
            else:
                fqdn_val = hostname
            
            mac_raw = host.get('mac', '')
            if isinstance(mac_raw, list):
                macs = mac_raw
            else:
                normalized = mac_raw.replace(',', '\n').replace(';', '\n').replace('\r', '\n').replace(' ', '\n')
                macs = [m.strip() for m in normalized.split('\n') if m.strip()]
            
            clean_macs = [ScanUtils.clean_mac(m).upper() for m in macs]
            
            row = {
                '#'                                  : '',
                'Component Type'                     : host['device_type'],
                'Asset Name'                         : fqdn_val,
                'Nickname'                           : '',
                'MAC Address'                        : '; '.join(clean_macs),
                'Asset IP Address'                   : host['ip'],
                'Public Facing'                      : 'No',
                'Public Facing FQDN'                 : '',
                'Public Facing IP Address'           : '',
                'Public Facing URL(s)'               : '',
                'Virtual Asset?'                     : '',
                'Manufacturer'                       : host['manufacturer'],
                'Model Number'                       : host['model'],
                'Serial Number'                      : host['serial'],
                'Line Item Number'                   : '',
                'National Stock Number'              : '',
                'OS/iOS/FW Version'                  : host['os'],
                'Memory Size / Type'                 : '',
                'Location (P/C/S & Building)'        : '',
                'Approval Status'                    : '',
                'Critical Information System Asset?' : ''
            }

            should_add = True
            replace_existing = False
            mac_to_replace = None

            for mac_clean in clean_macs:
                dedup_key = (fqdn_val.lower(), mac_clean)
                if dedup_key in host_mac_map:
                    existing_row = hardware[host_mac_map[dedup_key]]
                    if Utils.is_ip(existing_row["Asset Name"]) and not Utils.is_ip(fqdn_val):
                        replace_existing = True
                        mac_to_replace = mac_clean
                    else:
                        should_add = False
                        logging.info(f"ACAS Duplicate (hostname, MAC) detected, skipping: {dedup_key}")
                        break

            if replace_existing and mac_to_replace:
                dedup_key = (fqdn_val.lower(), mac_to_replace)
                hardware[host_mac_map[dedup_key]] = row
                logging.info(f"ACAS Replacing IP-only hostname row for MAC {mac_to_replace}")
            elif should_add:
                ip = row.get("Asset IP Address", "").strip()
                if ip in ip_only_placeholders:
                    idx = ip_only_placeholders[ip]
                    logging.info(f"Replacing placeholder row for IP {ip} with enriched row.")
                    hardware[idx] = row
                    for mac_clean in clean_macs:
                        dedup_key = (fqdn_val.lower(), mac_clean)
                        host_mac_map[dedup_key] = idx
                    del ip_only_placeholders[ip]
                else:
                    hardware.append(row)
                    new_idx = len(hardware) - 1
                    for mac_clean in clean_macs:
                        dedup_key = (fqdn_val.lower(), mac_clean)
                        host_mac_map[dedup_key] = new_idx
                        
        for idx, existing_row in enumerate(hardware):
            name = existing_row.get("Asset Name", "").strip()
            ip = existing_row.get("Asset IP Address", "").strip()
            mac = existing_row.get("MAC Address", "").strip()

            if mac == "" and Utils.is_ip(name) and name == ip:
                ip_only_placeholders[ip] = idx  # store row index   
                    
        # Aquire results from parseSCAP function in scan_parser.py out of scan pickle
        
        scap_scans = jmespath.search(
            "results[?type=='SCAP' || type=='CKL'].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os, mac: mac }",
            { 'results': scan_results }
        )

        for scan in scap_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            hostname = str(scan.get('hostname', '')).strip()
            if Utils.is_ip(hostname):
                fqdn_val = hostname
            elif '.' in hostname:
                fqdn_val = hostname.split('.')[0]
            else:
                fqdn_val = hostname

            mac_clean = ScanUtils.clean_mac(scan.get('mac', '')).upper()
            dedup_key = (fqdn_val.lower(), mac_clean)

            row = {
                '#'                                  : '',
                'Component Type'                     : scan['device_type'] if 'device_type' in scan and scan['device_type'].strip() != '' else 'Unknown',
                'Asset Name'                         : fqdn_val,
                'Nickname'                           : '',
                'MAC Address'                        : mac_clean,
                'Asset IP Address'                   : scan['ip'],
                'Public Facing'                      : 'No',
                'Public Facing FQDN'                 : '',
                'Public Facing IP Address'           : '',
                'Public Facing URL(s)'               : '',
                'Virtual Asset?'                     : '',
                'Manufacturer'                       : scan['manufacturer'],
                'Model Number'                       : scan['model'],
                'Serial Number'                      : scan['serial'],
                'Line Item Number'                   : '',
                'National Stock Number'              : '',
                'OS/iOS/FW Version'                  : scan['os'],
                'Memory Size / Type'                 : '',
                'Location (P/C/S & Building)'        : '',
                'Approval Status'                    : '',
                'Critical Information System Asset?' : ''
            }

            # Skip if any ACAS MAC matches this CKL MAC
            if mac_clean and any(mac_clean == key[1] for key in host_mac_map):
                logging.info(f"Skipping CKL/CKLB row for {fqdn_val} due to ACAS MAC match: {mac_clean}")
                continue

            if dedup_key in host_mac_map:
                existing_row = hardware[host_mac_map[dedup_key]]
                if Utils.is_ip(existing_row["Asset Name"]) and not Utils.is_ip(fqdn_val):
                    hardware[host_mac_map[dedup_key]] = row
                    logging.info(f"CKL/CKLB Replacing IP-only hostname row for MAC {mac_clean}")
                else:
                    logging.info(f"CKL/CKLB Duplicate (hostname, MAC) detected, skipping: {dedup_key}")
                continue

            ip = row.get("Asset IP Address", "").strip()
            if ip in ip_only_placeholders:
                idx = ip_only_placeholders[ip]
                logging.info(f"CKL/CKLB replacing placeholder row for IP {ip} with enriched row.")
                hardware[idx] = row
                host_mac_map[dedup_key] = idx
                del ip_only_placeholders[ip]
            else:
                hardware.append(row)
                new_idx = len(hardware) - 1
                host_mac_map[dedup_key] = new_idx

                
        hardware = sorted(hardware, key=lambda hardware: hardware['Asset Name'])
        for row in hardware:
            row['MAC Address'] = get_first_mac(row['MAC Address'])
            
        # Commented out per HW/SW instructions - No data in # column
        
        # hardware_count = 0
        # for asset in hardware:
            # hardware_count += 1
            # asset['#'] = hardware_count
         
        #<----Page Header Start---->#
         
        green_header = self.hwsw_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.hwsw_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.hwsw_workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.hwsw_workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.hwsw_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        worksheet.merge_range(0, 0, 0, 20, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            worksheet.write(1, col, '', gray_header_cells)
        worksheet.merge_range(1, 13, 1, 20, '', gray_header_merged) 
        
        worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        worksheet.write(2, 6, 'Office / Org:', gray_label)
        worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            worksheet.write(2, col, '', gray_header_cells)
        worksheet.merge_range(2, 13, 2, 20, '', gray_header_merged) 
        
        worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        worksheet.write(3, 6, 'POC Name:', gray_label)
        worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        worksheet.write(3, 12, '', gray_header_cells)
        worksheet.merge_range(3, 13, 3, 20, '', gray_header_merged) 
        
        worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        worksheet.write(4, 6, 'POC Phone:', gray_label)
        worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        worksheet.write(4, 12, '', gray_header_cells)
        worksheet.merge_range(4, 13, 4, 20, '', gray_header_merged) 
        
        worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            worksheet.write(5, col, '', gray_header_cells)
        worksheet.merge_range(5, 13, 5, 20, '', gray_header_merged) 
        
        #<----Page Header End---->#
        
        # Data writing from SCAP/ACAS results
        
        row = 6
        bold = self.hwsw_workbook.add_format({'font_size':12, 'bold': True, 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        wrap_text = self.hwsw_workbook.add_format({'font_size':11, 'text_wrap': True, 'border': 1})

        if hardware:
            col = 0
            for column_header in hardware[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in hardware:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
        
        # Dropdown Logic
                
        if "Yes No" in self.defined_names:
            yes_no_columns = {
                6: '',
                10: "This column indiciates if the asset is a virtual machine. If 'Yes' is selected, the Manufacturer, Model Number, and Serial Number columns should reflect, 'Virtual'.",
                20: 'In response to CP-2(8).1, please select Yes or No to annotate wheather or not this software is Critical Information System Asset.'
            }
            
            for col, tooltip in yes_no_columns.items():
                for r in range(7, row):
                    worksheet.data_validation(r, col, r, col, {
                        'validate': 'list',
                        'source': f'={self.defined_names["Yes No"]}',
                        'input_message': tooltip,
                        'show_input': True,
                        'show_error': True
                    })                
                
        if "Hardware Type" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 1, r, 1, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Hardware Type"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
                
        if "Approval" in self.defined_names:
            for r in range(7, row):
                worksheet.data_validation(r, 19, r, 19, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Approval"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
                
        # Combined Sheet

        logging.info("Generating Combined Software Sheet")
        combined_sheet = self.hwsw_workbook.add_worksheet('Software')

        # Build tab widths and handle extra tabs

        widths = [45, 31, 33, 31, 24, 28, 25, 24, 37, 40, 30, 39, 21, 39, 44, 43, 34, 31, 21, 24, 28, 22, 36, 28, 26, 26, 27, 26, 27, 36, 43, 44, 26, 27]
        ascii = string.ascii_uppercase

        def colnum_to_excel_col(n):
            """Convert column index (0-based) to Excel-style column name."""
            name = ''
            while n >= 0:
                name = chr(n % 26 + ord('A')) + name
                n = n // 26 - 1
            return name

        for index, w in enumerate(widths):
            col_letter = colnum_to_excel_col(index)
            combined_sheet.set_column(f"{col_letter}:{col_letter}", w)

        combined_sheet.autofilter(6, 0, 6, int(len(widths))-1)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)

        software = []

        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements
                }
            }""",
            { 'results' : scan_results }
        )

        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
                    QtGui.QGuiApplication.processEvents()

                hostname = host.get("hostname", "").strip()
                ip = host.get("ip", "").strip()
                system = hostname or ip

                for req in host.get('requirements', []):
                    plugin_id = req.get("plugin_id")
                    comments = req.get("comments", "").strip()
                    if not comments:
                        continue

                    # --- Linux: plugin 22869 ---
                    if plugin_id == 22869:
                        host_base_names = set()
                        for line in filter(None, comments.split("\n")):
                            line = line.strip()
                            if 'list of packages installed' in line:
                                continue
                                
                            pkg_match = re.match(r'^(.+)-([0-9][^-]*)-([^-|]+)\|', line)
                            if pkg_match:
                                name, version, release = pkg_match.groups()
                            else:
                                dpkg_match = re.match(r'^[a-z]{2}\s+(\S+)\s+(\S+)\s+(\S+)\s+.+$', line, re.IGNORECASE)
                                if dpkg_match:
                                    name, version, _arch = dpkg_match.groups()
                                    release = ''  # not used later
                                else:
                                    continue

                            if re.search(self.strings['IGN_SOFT'], name):
                                continue
                                
                            base_name = name.split('-')[0] if '-' in name else name
                            if '-' in name and base_name in host_base_names:
                                continue
                            host_base_names.add(base_name)                                

                            vendor_match = re.findall(r'\|([^|<]*?)<', line)
                            vendor = vendor_match[0].strip() if vendor_match else ''

                            software.append({
                                '#': '',
                                'Software Type': '',
                                'Software Vendor': vendor,
                                'Software Name': name,
                                'Version': version,
                                'Parent System': system,
                                'Subsystem': '',
                                'Network': '',
                                'Hosting Environment': '',
                                'Software Dependencies': '',
                                'Cryptographic Hash': '',
                                'In Service Date': '',
                                'IT Budget UII': '',
                                'Fiscal Year (FY)': '',
                                'POP End Date': '',
                                'License or Contract': '',
                                'License Term': '',
                                'Cost per License': '',
                                'Total Licenses': '',
                                'Total License Cost': '',
                                'Licenses Used': '',
                                'License POC': '',
                                'License Renewal Date': '',
                                'License Expiration Date': '',
                                'Approval Status': '',
                                'Approval Date': '',
                                'Release Date': '',
                                'Maintenance Date': '',
                                'Retirement Date': '',
                                'End of Life/Support Date': '',
                                'Extended End of Life/Support Date': '',
                                'Critical Information System Asset?': '',
                                'Location': '',
                                'Purpose': ''
                            })

                    # --- Windows: plugin 178102 ---
                    elif plugin_id == 178102:
                        for block in comments.split("\n\n"):
                            lines = block.strip().split("\n")
                            name = version = installed = vendor = ''

                            for i, line in enumerate(lines):
                                line = line.strip()

                                if line.startswith('- '):
                                    name = line[2:].strip()
                                elif '[DisplayVersion]' in line and i + 1 < len(lines):
                                    next_line = lines[i + 1].strip()
                                    if next_line.startswith("Raw Value") and ":" in next_line:
                                        version = next_line.split(":", 1)[1].strip()
                                elif '[InstallDate]' in line and i + 1 < len(lines):
                                    next_line = lines[i + 1].strip()
                                    if next_line.startswith("Raw Value") and ":" in next_line:
                                        raw_date = next_line.split(":", 1)[1].strip()
                                        try:
                                            installed = datetime.datetime.strptime(raw_date, "%Y/%m/%d").strftime("%Y-%m-%d")
                                        except Exception:
                                            installed = ''
                                elif '[Publisher]' in line and i + 1 < len(lines):
                                    next_line = lines[i + 1].strip()
                                    if next_line.startswith("Raw Value") and ":" in next_line:
                                        vendor = next_line.split(":", 1)[1].strip()

                            if name and version and re.search(self.strings['IGN_SOFT'], name) is None:
                                software.append({
                                    '#': '',
                                    'Software Type': '',
                                    'Software Vendor': vendor,
                                    'Software Name': name,
                                    'Version': version,
                                    'Parent System': system,
                                    'Subsystem': '',
                                    'Network': '',
                                    'Hosting Environment': '',
                                    'Software Dependencies': '',
                                    'Cryptographic Hash': '',
                                    'In Service Date': installed,
                                    'IT Budget UII': '',
                                    'Fiscal Year (FY)': '',
                                    'POP End Date': '',
                                    'License or Contract': '',
                                    'License Term': '',
                                    'Cost per License': '',
                                    'Total Licenses': '',
                                    'Total License Cost': '',
                                    'Licenses Used': '',
                                    'License POC': '',
                                    'License Renewal Date': '',
                                    'License Expiration Date': '',
                                    'Approval Status': '',
                                    'Approval Date': '',
                                    'Release Date': '',
                                    'Maintenance Date': '',
                                    'Retirement Date': '',
                                    'End of Life/Support Date': '',
                                    'Extended End of Life/Support Date': '',
                                    'Critical Information System Asset?': '',
                                    'Location': '',
                                    'Purpose': ''
                                })

        software = sorted(software, key=lambda s: (s['Software Name'].lower().strip(), s['Version']))
        
        #<----Page Header Start---->#
         
        green_header = self.hwsw_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.hwsw_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.hwsw_workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.hwsw_workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.hwsw_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        combined_sheet.merge_range(0, 0, 0, 33, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        combined_sheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        combined_sheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            combined_sheet.write(1, col, '', gray_header_cells)
        combined_sheet.merge_range(1, 13, 1, 33, '', gray_header_merged) 
        
        combined_sheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        combined_sheet.merge_range(2, 2, 2, 5, '', normal_cell)
        combined_sheet.write(2, 6, 'Office / Org:', gray_label)
        combined_sheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            combined_sheet.write(2, col, '', gray_header_cells)
        combined_sheet.merge_range(2, 13, 2, 33, '', gray_header_merged) 
        
        combined_sheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        combined_sheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        combined_sheet.write(3, 6, 'POC Name:', gray_label)
        combined_sheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        combined_sheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        combined_sheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        combined_sheet.write(3, 12, '', gray_header_cells)
        combined_sheet.merge_range(3, 13, 3, 33, '', gray_header_merged) 
        
        combined_sheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        combined_sheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        combined_sheet.write(4, 6, 'POC Phone:', gray_label)
        combined_sheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        combined_sheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        combined_sheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        combined_sheet.write(4, 12, '', gray_header_cells)
        combined_sheet.merge_range(4, 13, 4, 33, '', gray_header_merged) 
        
        combined_sheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        combined_sheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        combined_sheet.write(5, 6, 'POC E-Mail:', gray_label)
        combined_sheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            combined_sheet.write(5, col, '', gray_header_cells)
        combined_sheet.merge_range(5, 13, 5, 33, '', gray_header_merged) 
        
        #<----Page Header End---->#
        
        row = 6
        bold = self.hwsw_workbook.add_format({'font_size':12, 'bold': True, 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        wrap_text = self.hwsw_workbook.add_format({'font_size':11, 'text_wrap': True, 'border': 1})

        if software:
            col = 0
            for column_header in software[0]:
                combined_sheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in software:
                col = 0
                for value in result:
                    combined_sheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
                
        # Dropdown Logic
                
        if "Yes No" in self.defined_names:
            yes_no_columns = {
                31: 'In response to CP-2(8).1, please select Yes or No to annotate wheather or not this software is Critical Information System Asset.'
            }
            
            for col, tooltip in yes_no_columns.items():
                for r in range(7, row):
                    combined_sheet.data_validation(r, col, r, col, {
                        'validate': 'list',
                        'source': f'={self.defined_names["Yes No"]}',
                        'input_message': tooltip,
                        'show_input': True,
                        'show_error': True
                    }) 
        
        if "Software Type" in self.defined_names:
            for r in range(7, row):
                combined_sheet.data_validation(r, 1, r, 1, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Software Type"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
                
        if "Approval" in self.defined_names:
            for r in range(7, row):
                combined_sheet.data_validation(r, 24, r, 24, {
                    'validate': 'list',
                    'source': f'={self.defined_names["Approval"]}',
                    'input_message': 'Select a type from the list or input your own by typing directly in the cell.',
                    'show_input': True,
                    'show_error': True
                })
         
        # Create instruction sheet
        
        instruction_sheet = self.hwsw_workbook.add_worksheet('Instructions')
        
        instruction_content = [
            "1. Enter valid information into the fields on the Hardware/Software Import Template.",
            "2. Do not delete columns/sheets, delete the classification label, or add additional columns. Doing so may have a negative impact on the ability for eMASS to ingest the template.",
            "3. The following fields/columns contain drop-down menus that allow for selection of existing values in the eMASS instance: \"Component Type\", \"Software Type\", \"Approval Status\". If no existing value is appropriate, manually enter a new value.",
            "4. The \"Asset ID #\" (Column A) is automatically generated by eMASS after the hardware or software asset is successfully imported.  No user action is required to complete or update and therefore this column can be treated as read-only.",
            "5. If importing hardware information, the \"Asset Name\" is a required field.",
            "6. If either \"Manufacturer\" or \"Model Number\" is specified for a hardware asset then both fields become required.",
            "7. Selecting 'Yes' for \"Virtual Asset\" on a hardware entry will set the Manufacturer/Model Number/Serial Number fields as 'Virtual'. Those fields can be manually adjusted thereafter if necessary.",
            "8. If importing software information, the \"Software Vendor\", \"Software Name\", and \"Version\" are required fields.",
            "9. When importing software information, only integers of 0 and above are accepted for \"Total Licenses\" and \"Licenses Used\".",
            "10. The \"Virtual Asset\" and \"Critical Information Asset\" fields have a drop-down with expected input values.",
            "11. To the greatest extent possible, ensure all spelling and name usage is correct. When entering product names, please use the formal/official version rather than an abbreviation (e.g., \"Windows 10 Home (64-Bit)\" rather than \"Win10 64\")).",
            "12. For additional information on defining critical information system assets, refer to CP-2(8), \"Identify Critical Assets\".",
            "13. The following hardware fields are conditionally hidden unless \"Yes\" is selected for \"Public Facing\": \"Public Facing FQDN\", \"Public Facing IP Address\", and \"Public Facing URL(s)\".",
            "14. Most hardware fields have a character limit of 100 with the exception of \"MAC Address\", \"Public Facing FQDN\", \"Public Facing IP Address\", and \"Location (P/C/S & Building)\" which have a character limit of 250 and \"Public Facing URL(s)\" has a character limit of 750. \"Line Item Number\" has a character limit of 6 per value, but can have multiple values separated by a semi-colon. \"National Stock Number\" has a character limit of 16 per value (format XXXX-XX-XXX-XXXX),  but can have multiple values separated by a semi-colon.",
            "15. Most software fields have a character limit of 100 with the exception of \"License or Contract\" and \"Location\" which have a character limit of 250, \"IT Budget UII\" which has a character limit of 50, and \"Fiscal Year (FY)\" which has a character limit of 20.",
            "16. If set, the \"Extended End of Life/Support Date\" cannot occur prior to the \"End of Life/Support Date\".",
            "17. The fields \"Cost per License\" and \"Total Cost\" require a numeric value that does not exceed 15 digits and 2 decimal places.",
        ]
        
        bold_format = self.hwsw_workbook.add_format({'bold': True, 'font_size': 20, 'font_name': 'Times New Roman', 'border': 1})
        normal_format = self.hwsw_workbook.add_format({'text_wrap': True, 'font_size': 11, 'font_name': 'Calibri'})
        
        instruction_sheet.write(0, 0, 'Hardware/Software Import Template Instructions', bold_format)
        
        for i, line in enumerate(instruction_content, start=2):
            instruction_sheet.write(f"A{i}", line, normal_format)
            
        instruction_sheet.set_column('A:A', 152)

    def generate_ppsm_workbook(self):
        """ Generates PPS Workbook """
        if 'rpt_ppsm' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building PPS workbook')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_name = os.path.join(self.report_dir, "PPSM.xlsx")
        self.ppsm_workbook = xlsxwriter.Workbook(summary_name)
        ppsm_worksheet = self.ppsm_workbook.add_worksheet('PPS')
        
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'PPS' Workbook")

        widths = [30, 30, 30, 30, 30]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            ppsm_worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
        
        self.service_map = (
            self.scar_data
                .get("data_mapping", {})
                .get("common_services", {})
        )
        
        # Load dynamic plugin list
        dynamic_plugin_path = os.path.join(self.scar_conf.get('application_path'), "data", "dynamic_plugins.json")
        try:
            with open(dynamic_plugin_path, "r") as f:
                service_plugins = set(json.load(f))
            if not service_plugins:
                service_plugins = {11219}
                logging.warning("[PPS-WB] dynamic_plugins.json is empty, falling back to 11219")
            else:
                logging.info(f"[PPS-WB] Loaded {len(service_plugins)} dynamic plugins")
        except Exception as e:
            service_plugins = set()
            logging.warning(f"[PPS-WB] Could not load dynamic_plugins.json: {e}")
        
        # logging.debug(f"[PPS-WB] 1st five Keys in service map {list(self.service_map.keys())[:5]}")
            
        ppsm_worksheet.autofilter(6, 0, 6, int(len(widths))-1)

        ports = []
        
        for result in scan_results:
            if result.get("type") != "ACAS":
                continue
            for host in result.get("hosts", []):
                for req in host.get("requirements", []):
                    if req.get("plugin_id") in service_plugins:
                        port = str(req.get("port")).strip()
                        proto = req.get("protocol", "").strip().lower()
                        key = f"{port}/{proto}"
                        service = self.service_map.get(key)
                        if service is None:
                            service = req.get("service", "")
                            # logging.debug(f"[PPSM] No service match for {key} (using plugin service)")
                        service = service.rstrip("?")
                        if not service or service.lower() == "unknown":
                            service = ""
                        else:
                            service = service.upper()
                        row = {
                            "Port": port,
                            "Originating IP Address": "",
                            "Destination IP Address": host.get("ip", ""),
                            "Protocol": proto,
                            "Service": service
                        }
                        ports.append(row)

                # Add netstat-derived entries
                for conn in host.get("netstat", []):
                    proto = (conn.get("proto") or "").strip().lower()
                    port = str(conn.get("dest_port")).strip()
                    row = {
                        "Port": port,
                        "Originating IP Address": conn.get("origin_ip"),
                        "Destination IP Address": conn.get("dest_ip"),
                        "Protocol": proto,
                        "Service": ""
                    }
                    if not row["Service"]:
                        key = f"{port}/{proto}"
                        # logging.debug(f"[PPSM] Built Key: '{key}' -- In map: {key in self.service_map}")
                        if key not in self.service_map:
                            # logging.debug(f"[PPSM] No service match for {key}")
                            pass
                        row["Service"] = self.service_map.get(key, "")
                    ports.append(row)
        
        # Refine with vendor_ports.json if exist
        
        def load_vendor_rules(path):
            try:
                with open(path, "r") as f:
                    rules = json.load(f)
            except FileNotFoundError:
                logging.warning(f"[PPS] vendor_ports.json not found at {path}")
                return []
            except json.JSONDecodeError as jde:
                logging.error(f"[PPS] JSON syntax error in vendor_ports.json: {jde}")
                return []
            except Exception as e:
                logging.error(f"[PPS] Unexpected error loading vendor_ports.json: {e}")
                return []
            if not isinstance(rules, list):
                logging.error("[PPS] vendor_ports.json loaded but does not contain a top level list")
                return []
              
            logging.info(f"[PPS] Successfully loaded {len(rules)} vendor rules from vendor_ports.json")
            return rules
                
        def ip_matches(ip, ip_rules):
            if not ip or not ip_rules:
                return False
            ip = ip.strip()
            for rule_ip in ip_rules:
                rule_ip = rule_ip.strip()
                try:
                    if '/' in rule_ip:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(rule_ip, strict=False):
                            return True
                    elif ip == rule_ip:
                        return True
                except Exception:
                    continue
            return False

        def ip_in_range(ip, range_str):
            try:
                start_ip, end_ip = [ipaddress.IPv4Address(x.strip()) for x in range_str.split("-")]
                ip_obj = ipaddress.IPv4Address(ip)
                return start_ip <= ip_obj <= end_ip
            except Exception:
                return False
         
        def any_ip_matches(row_ips: str, rule_ips: list) -> bool:
            try:
                row_ip_list = [ip.strip() for ip in row_ips.split(',') if ip.strip()]
                for row_ip in row_ip_list:
                    for rule_ip_entry in rule_ips:
                        for rule_ip in rule_ip_entry.split(','):
                            rule_ip = rule_ip.strip()
                            if '/' in rule_ip:
                                if ipaddress.ip_address(row_ip) in ipaddress.ip_network(rule_ip):
                                    return True
                            elif '-' in rule_ip:
                                if ip_in_range(row_ip, rule_ip):
                                    return True
                            elif row_ip == rule_ip:
                                return True
                return False
            except Exception:
                return False
                
        def extract_port_number(port_str):
            try:
                # If single integer port, return it
                return int(port_str)
            except ValueError:
                # If range, return start of range as sort key
                match = re.match(r"(\d+)", port_str)
                if match:
                    return int(match.group(1))
                return 0
            
        # Apply transformation rules if vendor_rules exist
        
        vendor_rules_path = os.path.join(self.scar_conf.get('application_path'), "data", "vendor_ports.json")
        vendor_rules = load_vendor_rules(vendor_rules_path)
        
        consolidated = []   
        used_rows = set()
        if vendor_rules:
            consolidated = []
            logging.info(f"[PPS] Applying {len(vendor_rules)} vendor rules from vendor_ports.json")
            
            for rule in vendor_rules:
                matched_rows = []
                for idx, row in enumerate(ports):
                    proto = row["Protocol"]
                    try:
                        port_int = int(row["Port"])
                    except ValueError:
                        continue
                    if row["Protocol"].lower() != rule["protocol"].lower():
                        continue
                    if "ports" in rule:
                        if port_int not in rule["ports"]:
                            continue
                    if "port_range" in rule:
                        if not (rule["port_range"][0] <= port_int <= rule["port_range"][1]):
                            continue
                    if "dest_ips" in rule:
                        if "dest_ips" in rule and not any_ip_matches(row["Destination IP Address"], rule["dest_ips"]):
                            continue
                    if "origin_ips" in rule:
                        # Only apply rule if data actually has origin IP for comparison
                        origin_raw = row["Originating IP Address"].strip()
                        if not origin_raw:
                            continue
                        if not any_ip_matches(origin_raw, rule["origin_ips"]):
                                continue
                            
                    used_rows.add(idx)
                    matched_rows.append((idx, row))
                    
                if matched_rows:
                    port_nums = sorted({int(r["Port"]) for _, r in matched_rows})
                    port_str = f"{port_nums[0]}-{port_nums[-1]}" if len(port_nums) > 1 else (port_nums[0])
                    origin_ips = sorted({r["Originating IP Address"].strip() for _, r in matched_rows if r["Originating IP Address"].strip()})
                    dest_ips = sorted({r["Destination IP Address"].strip() for _, r in matched_rows if r["Destination IP Address"].strip()})
                
                    direction = rule.get("direction", "inbound")
                    
                    if direction == "outbound":
                        origin = ", ".join(origin_ips)
                        dest = ", ".join(dest_ips)
                    elif direction == "inbound":
                        # If rule explicitly specifies origin_ips, honor reversal
                        if "origin_ips" in rule:
                            origin = ", ".join(dest_ips)
                            dest = ", ".join(origin_ips)
                        else:
                            # No origin_ips specified — likely listener — collapse all dest IPs, clear origin
                            origin = ""
                            dest = ", ".join(dest_ips)
                    elif direction == "both":
                        # Treat bidirectional ports as inbound
                        if "origin_ips" in rule:
                            origin = ", ".join(dest_ips)
                            dest = ", ".join(origin_ips)
                        else:
                            # No origin_ips specified — likely listener — collapse all dest IPs, clear origin
                            origin = ""
                            dest = ", ".join(dest_ips)
                    consolidated.append({
                        "Port": port_str,
                        "Originating IP Address": origin,
                        "Destination IP Address": dest,
                        "Protocol": rule["protocol"],
                        "Service": rule["service"]
                    })
                
        for idx, row in enumerate(ports):
            if idx not in used_rows:
                if consolidated is not None:
                    consolidated.append({
                        "Port": row["Port"],
                        "Originating IP Address": row["Originating IP Address"],
                        "Destination IP Address": row["Destination IP Address"],
                        "Protocol": row["Protocol"],
                        "Service": row["Service"]
                    })   

                #<----Page Header Start---->#
         
        green_header = self.ppsm_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.ppsm_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.ppsm_workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.ppsm_workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.ppsm_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })
        
        gray_header_merged_bottom_right = self.ppsm_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1,
            'bottom': 1
        })

        ppsm_worksheet.merge_range(0, 0, 0, 20, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        ppsm_worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        ppsm_worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            ppsm_worksheet.write(1, col, '', gray_header_cells)
        ppsm_worksheet.merge_range(1, 13, 1, 20, '', gray_header_merged) 
        
        ppsm_worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        ppsm_worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        ppsm_worksheet.write(2, 6, 'Office / Org:', gray_label)
        ppsm_worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            ppsm_worksheet.write(2, col, '', gray_header_cells)
        ppsm_worksheet.merge_range(2, 13, 2, 20, '', gray_header_merged) 
        
        ppsm_worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        ppsm_worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        ppsm_worksheet.write(3, 6, 'POC Name:', gray_label)
        ppsm_worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        ppsm_worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        ppsm_worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        ppsm_worksheet.write(3, 12, '', gray_header_cells)
        ppsm_worksheet.merge_range(3, 13, 3, 20, '', gray_header_merged) 
        
        ppsm_worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        ppsm_worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        ppsm_worksheet.write(4, 6, 'POC Phone:', gray_label)
        ppsm_worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        ppsm_worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        ppsm_worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        ppsm_worksheet.write(4, 12, '', gray_header_cells)
        ppsm_worksheet.merge_range(4, 13, 4, 20, '', gray_header_merged) 
        
        ppsm_worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        ppsm_worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        ppsm_worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        ppsm_worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        # for col in range(9, 13):
            # ppsm_worksheet.write(5, col, '', gray_header_cells)
        ppsm_worksheet.merge_range(5, 9, 5, 20, '', gray_header_merged_bottom_right) 
        
        #<----Page Header End---->#

        row = 6
        bold = self.ppsm_workbook.add_format({'bold': True, 'font_size': 12, 'border': 1})
        wrap_text = self.ppsm_workbook.add_format({'font_size': 12, 'text_wrap': True, 'border': 1})
        
        ppsm_worksheet.write(row, 0, "Port", bold)
        ppsm_worksheet.write(row, 1, "Originating IP Address", bold)
        ppsm_worksheet.write(row, 2, "Destination IP Address", bold)
        ppsm_worksheet.write(row, 3, "Protocol", bold)
        ppsm_worksheet.write(row, 4, "Service", bold)
        row += 1
        
        # Apply vendor-agnositc consolidation 
        
        original_rows = consolidated if consolidated else ports
        grouped = defaultdict(list)
        
        for entry in original_rows:
            key = (
                str(entry["Port"]).strip(),
                str(entry["Protocol"]).strip().lower(),
                str(entry["Service"]).strip().lower()
            )
            grouped[key].append(entry)
            
        row_data_list = []
        for key, rows in grouped.items():
            active_rows = []
            passive_rows = []
            for r in rows:
                has_active_conn = bool(str(r["Originating IP Address"]).strip()) and bool(str(r["Destination IP Address"]).strip())
                if has_active_conn:
                    active_rows.append(r)
                else:
                    passive_rows.append(r)
                    
            row_data_list.extend(active_rows)
            
            if passive_rows:
                dest_set = sorted({
                    str(r["Destination IP Address"]).strip()
                    for r in passive_rows if str(r["Destination IP Address"]).strip()
                })
                if dest_set:
                    row_data_list.append({
                        "Port": key[0],
                        "Originating IP Address": "",
                        "Destination IP Address": ", ".join(dest_set),
                        "Protocol": key[1],
                        "Service": key[2]
                    })
        
        row_data_list.sort(key=lambda x: (
            extract_port_number(x["Port"]),
            x["Protocol"].lower(), 
            x["Destination IP Address"]
        ))
        
        seen_rows = set()
        
        for row_data in row_data_list:
            origin_ip = str(row_data["Originating IP Address"]).strip()
            dest_ip = str(row_data["Destination IP Address"]).strip()
            
            row_key = (
                str(row_data["Port"]).strip(),
                origin_ip,
                dest_ip,
                str(row_data["Protocol"]).strip().lower(),
                str(row_data["Service"]).strip().lower()
            )
            
            # Skip self-connections or exact duplicates
            if origin_ip and dest_ip and origin_ip == dest_ip:
                continue
            if str(row_data["Port"]).strip() == "0":
                continue
            if row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            
            ppsm_worksheet.write(row, 0, str(row_data["Port"]), wrap_text)
            ppsm_worksheet.write(row, 1, origin_ip, wrap_text)
            ppsm_worksheet.write(row, 2, dest_ip, wrap_text)
            ppsm_worksheet.write(row, 3, str(row_data["Protocol"]), wrap_text)
            ppsm_worksheet.write(row, 4, str(row_data["Service"]).lower(), wrap_text)
            row += 1
            
    def generate_poam_workbook(self):
        """ Generates POAM """
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_name = os.path.join(self.report_dir, "POA&M.xlsx")
        self.poam_workbook = xlsxwriter.Workbook(summary_name)
        
        # Add hidden list sheet
        hidden_sheet = self.poam_workbook.add_worksheet('(U) Lists')
        hidden_sheet.hide()
        
        dropdown_data = {
            'Raw Severity': ['I', 'II', 'III'],
            'levels': ['Very Low', 'Low', 'Moderate', 'High', 'Very High'],
            'status': ['Completed', 'Ongoing', 'Not Applicable', 'Archived', 'Risk Accepted']
        }
        
        for col_idx, (name, values) in enumerate(dropdown_data.items()):
            for row_idx, value in enumerate(values):
                hidden_sheet.write(row_idx, col_idx, value)
                
            # Create named range with no spaces
            named_range = name.replace(" ", "")
            col_letter = xl_col_to_name(col_idx)
            self.poam_workbook.define_name(
                named_range,
                f"'(U) Lists'!${col_letter}$1:${col_letter}${len(values)}"
            )

        ### Generates the POAM Tab
        
        if 'rpt_poam' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building POAM')
        poam_worksheet = self.poam_workbook.add_worksheet('POA&M')
        poam_worksheet.activate()
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'POAM' Workbook")
            QtGui.QGuiApplication.processEvents()

        widths = [1, 14, 40, 18, 25, 25, 25, 30, 15, 30, 45, 20, 30, 25, 75, 40, 40, 25, 25, 40, 25, 25, 40, 25, 40, 50]
                 
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            poam_worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        poam_worksheet.autofilter(6, 0, 6, int(len(widths))-1)

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        q = Queue(maxsize=0)
        poam_results = {'O'  : {}, 'NA' : {}, 'NR' : {}, 'E'  : {}, 'C'  : {}}

        def get_scan(queue, poam_results, scan_results):
            while not queue.empty():
                work = queue.get()

                status = work[0]
                type = work[1]
                if type == 'disa':
                    disa_scans = jmespath.search(
                        "results[?type=='SCAP' || type=='CKL'].{ policy: policy, scanner_edition: scanner_edition, scan_description: description, type: type, hostname: hostname, filename: filename, requirements: requirements[] | [?status=='" + status + "'].{ req_title: req_title, cci: cci, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, description: description, version: version, release: release, stig_id: stigid, stig_uuid: uuid, stig_classification: classification, scan_title: title } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['rule_id']) not in poam_results[status]:
                                poam_results[status][str(req['rule_id'])] = {
                                    'scan_title'      : req['scan_title'],
                                    'grp_id'          : req['grp_id'],
                                    'vuln_id'         : req['vuln_id'],
                                    'rule_id'         : req['rule_id'],
                                    'plugin_id'       : req['plugin_id'],
                                    'cci'             : req['cci'],
                                    'iavm'            : '',
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['rule_id']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scanner_edition'],
                                'hostname'        : scan['hostname'],
                                'version'         : req['version'],
                                'release'         : req['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scanner_edition: '', scan_description: '', type: type, version: version, release: feed, filename: filename, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [?status=='" + status + "'].{ cci: cci, req_title: req_title, description: description, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, iavm: iavm, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, publication_date: publication_date, modification_date: modification_date, rmf_controls: rmf_controls } } }",
                        { 'results' : scan_results}
                    )
                    
                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                # debugging
                                # logging.debug(f"[ACAS] Plugin ID: {req.get('plugin_id')}")
                                # logging.debug(f"[ACAS] GRP_ID: {req.get('grp_id')}")
                                # logging.debug(f"[ACAS] CCI: {req.get('cci')}")
                                # logging.debug(f"[ACAS] RMF Controls: {req.get('rmf_controls')}")
                                # logging.debug(f"[ACAS] Requirement Keys: {list(req.keys())}")
                                if 'rmf_controls' not in req:
                                    logging.warning(f"[ACAS] Missing 'rmf_controls' for plugin {req.get('plugin_id')}")
                                elif not isinstance(req['rmf_controls'], list):
                                    logging.warning(f"[ACAS] 'rmf_controls' not a list for plugin {req.get('plugin_id')}: {req.get('rmf_controls')}")

                                if str(req['plugin_id']) not in poam_results[status]:
                                    poam_results[status][str(req['plugin_id'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grp_id'],
                                        'vuln_id'         : req['vuln_id'],
                                        'rule_id'         : req['rule_id'],
                                        'plugin_id'       : req['plugin_id'],
                                        'cci'             : req['cci'],
                                        'iavm'            : req['iavm'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'publication_date'  : req['publication_date'],
                                        'modification_date' : req['modification_date'],
                                        'rmf_controls'      :(req['rmf_controls'][0] if 'rmf_controls' in req and isinstance(req['rmf_controls'], list) and req['rmf_controls']else self.scar_data.get('acas_control', {}).get(req.get('grp_id', ''), '')),
                                        'results'         : [],
                                    }
                                    # logging.debug(f"[RMF FINAL] Plugin ID: {req['plugin_id']} | Family: {req['grp_id']} | RMF: {poam_results[status][str(req['plugin_id'])]['rmf_controls']}")

                                poam_results[status][ str(req['plugin_id']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scanner_edition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_threads = int(psutil.cpu_count()) * 2
        for i in range(num_threads):
            worker = Thread(target=get_scan, args=(q, poam_results, scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )


        selected_mitigations = {}
        for mit in self.scar_data.get('mitigations', {}).get('mitigations', []):
            if mit.get('plugin_id', '').strip():
                selected_mitigations[str(mit['plugin_id'])] = mit['mitigation']
            if mit.get('vuln_id', '').strip():
                selected_mitigations[str(mit['vuln_id'])] = mit['mitigation']
            if mit.get('rule_id', '').strip():
                selected_mitigations[str(mit['rule_id'])] = mit['mitigation']
                    
        selected_impacts = {}
        for impact in self.scar_data.get('impacts', {}).get('impacts', []):
            if impact.get('plugin_id', '').strip():
                selected_impacts[str(impact['plugin_id'])] = impact['impact']
            if impact.get('vuln_id', '').strip():
                selected_impacts[str(impact['vuln_id'])] = impact['impact']
            if impact.get('rule_id', '').strip():
                selected_impacts[str(impact['rule_id'])] = impact['impact']
                
        selected_resources = {}
        for resource in self.scar_data.get('resources', {}).get('resources', []):
            if resource.get('plugin_id', '').strip():
                selected_resources[str(resource['plugin_id'])] = resource['resource']
            if resource.get('vuln_id', '').strip():
                selected_resources[str(resource['vuln_id'])] = resource['resource']
            if resource.get('rule_id', '').strip():
                selected_resources[str(resource['rule_id'])] = resource['resource']
                        
        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]
                
                rmf_controls = req.get('rmf_controls', '')
                if rmf_controls == '':
                    rmf_controls = req.get('rmf_controls') or self.scar_data.get('data_mapping', {}).get('ap_mapping', {}).get(req['cci'], '')

                hosts = []
                types = []
                comments = []
                finding_details = []
                for host in req['results']:
                    if self.scar_conf.get('host_details'):
                        hosts.append(f"{host['hostname']} [{host['type']} - Ver: {host['version']}, Rel/Feed: {host['release']} ]")
                    else:
                        hosts.append(f"{host['hostname']}")
                    
                    types.append(f"{host['type']}")
                    comments.append(f"{host['comments']}")
                    finding_details.append(f"{host['finding_details']}")

                hosts = "\n".join(hosts)
                types = list(set(types))
                prefix = "/".join(types)
                comments = "\n\n".join( list(set([c for c in comments if c])) )
                finding_details = "\n\n".join( list(set([f for f in finding_details if f])) )

                # pylint: disable=C0330
                scd = ""
                if self.scar_conf.get('scd'):
                    if self.scar_conf.get('lower_risk'):
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                    else:
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )
                else:
                    scd = ''

                predisposing_conditions = self.scar_conf.get('predisposing_conditions')
                
                mitigation_statement = ''
                if self.scar_conf.get('mitigation_statements') == 'poam':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                elif self.scar_conf.get('mitigation_statements') == 'ckl' and 'ckl' in req['results'][0]['type'].lower():
                    mitigation_statement = comments
                elif self.scar_conf.get('mitigation_statements') == 'both':
                    if str(req['plugin_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                    if str(req['vuln_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                    if str(req['rule_id']) in selected_mitigations.keys():
                        mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                    if mitigation_statement.strip() == '' and 'ckl' in req['results'][0]['type'].lower():
                        mitigation_statement = comments
                        
                # logging.debug(f"[MITIGATION] Loaded {len(mitigation_statement)} mitigation entries")
                        
                impact_statement = ''
                if selected_impacts:  # only run if there's data
                    if str(req.get('plugin_id')) in selected_impacts:
                        impact_statement = selected_impacts[str(req['plugin_id'])]
                    elif str(req.get('vuln_id')) in selected_impacts:
                        impact_statement = selected_impacts[str(req['vuln_id'])]
                    elif str(req.get('rule_id')) in selected_impacts:
                        impact_statement = selected_impacts[str(req['rule_id'])]
                        
                # logging.debug(f"[IMPACT] Loaded {len(selected_impacts)} impact entries")
                
                resource_import_statement = ''
                if selected_resources:  # only run if there's data
                    if str(req.get('plugin_id')) in selected_resources:
                        resource_import_statement = selected_resources[str(req['plugin_id'])]
                    elif str(req.get('vuln_id')) in selected_resources:
                        resource_import_statement = selected_resources[str(req['vuln_id'])]
                    elif str(req.get('rule_id')) in selected_resources:
                        resource_import_statement = selected_resources[str(req['rule_id'])]
                        
                # logging.debug(f"[RESOURCE] Loaded {len(selected_resources)} resource entries")
                
                if self.scar_conf.get('test_results') is not None:
                    #test results parsed
                    
                    if req['cci'].strip() != '':
                        #cci is present
                        
                        if(
                            self.scar_conf.get('test_results') == 'add' or
                            (
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str)
                            )
                        ):
                            #add option selected, proceed as normal
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            
                        elif self.scar_conf.get('test_results') == 'close':
                            #close option selected, inheritted or CCI's not in package will be closed.
                            #non-inheritted controls that are present will proceed as normal
                            
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and 
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to close
                                comments = f"{ req['cci']}\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being marked as 'Completed' by default. \n\n{comments}"
                                rmf_controls = rmf_controls
                                status = f"{ Utils.status('C', 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"{ req['cci']}\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being marked as completed by default. \n\n{comments}"
                                    rmf_controls = rmf_controls
                                    status = f"{ Utils.status('C', 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        elif self.scar_conf.get('test_results') == 'convert':
                            #convert option selected, inheritted or CCI's not in package will be converted to CM-6.5
                            #non-inheritted controls that are present will proceed as normal
                            if(
                                isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                not isinstance(self.scar_data.get('test_result_data'), str) and 
                                req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys()
                            ):
                                #the current cci is not in the implementation plan, map to CM-6.5
                                comments = f"CCI-000366\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being mapped to CCI-000366 CM-6.5.\n\n{comments}"
                                req['cci'] = 'CCI-000366'
                                rmf_controls = "CM-6.5"
                                status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                                if(
                                    isinstance(self.scar_data.get('test_result_data'), Iterable) and 
                                    not isinstance(self.scar_data.get('test_result_data'), str) and 
                                    (
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                        self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                    )
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"CCI-000366\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being mapped to CCI-000366 CM-6.5. \n\n{comments}"
                                    req['cci'] = 'CCI-000366'
                                    rmf_controls = "CM-6.5"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        else:
                            #fallthrough catch.  This should never be reached
                            
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    else:
                        #no cci present, convert to CM-6.5
                        rmf_controls = 'CM-6.5'
                        req['cci'] = 'CCI-000366'
                        comments = f"{req['cci']}\n\nThe control mapping for this requirement is unavailable so it is being mapped to CCI-000366 CM-6.5 by default. \n\n{comments}"
                        status = f"{ Utils.status(req['status'], 'HUMAN') }"

                else:
                    # logging.debug(f"[REPORT] Plugin family: {req.get('grp_id')}, RMF Control: {rmf_controls}")
                    # test results not submitted, process as usual
                    rmf_controls = rmf_controls
                    comments = f"{ req['cci']}\n\n{comments}"
                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    
                if self.scar_conf.get('include_finding_details'):
                    comments = f"{comments}\n\nFinding Details:\n{finding_details}"
                
                if req.get('status', '').strip().lower() in ['closed', 'c']:
                    continue
                    
                # Handle Mitigation risk lowering
                is_na = str(req.get('status', '')).strip().lower() in ['not applicable', 'na']
                has_mitigation = mitigation_statement.strip() !=''
                
                if is_na:
                    residual_risk = ''
                elif has_mitigation and self.scar_conf.get('lower_risk'):
                    lowered_numeric = Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) -1), 0, 3)
                    residual_risk = Utils.risk_val(str(lowered_numeric), 'POAM')
                else:
                    residual_risk = ''
                
                
                # Calculate Relevance of Threat
                ordinal = {'very low': 1, 'low': 2, 'moderate': 3, 'high': 4, 'very high': 5}
                reverse = {1: 'very low', 2: 'Low', 3: 'Moderate', 4: 'High', 5: 'Very High'}

                sev = ordinal.get(Utils.risk_val(req['severity'], 'POAM').lower(), 1)
                likelihood = ordinal.get(Utils.risk_val(req['severity'], 'POAM').lower(), 1)
                impact = ordinal.get(Utils.risk_val(req['severity'], 'POAM').lower(), 1)

                total_risk = sev + likelihood + impact
                    
                avg = math.ceil(total_risk / 3)
                    
                relevance = reverse.get(avg, 'Medium')

                req_data = {
                    'A'                                                 : '',
                    'POA&M Item ID'                                     : '',
                    'Control Vulnerability Description'                 : f"Title: {req['req_title']}\n{req['iavm']}\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Security Control Number (NC/NA controls only)'     : rmf_controls,
                    'Office/Org'                                        : f"{self.scar_data.get('command')}\n{self.scar_data.get('name')}\n{self.scar_data.get('phone')}\n{self.scar_data.get('email')}\n".strip(),
                    'Security Checks'                                   : f"{req['plugin_id']}{req['rule_id']}\n{req['vuln_id']}",
                    'Resources Required'                                : "None" if is_na else f"{req['resources']}" or resource_import_statement,
                    'Scheduled Completion Date'                         : "" if is_na else scd,
                    'Milestone with Completion Dates'                   : "" if is_na else "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
                                                                                                                                        s=str(scd).split('-'),
                                                                                                                                        m=(['Quarter One', 'Quarter Two', 'Quarter Three', 'Quarter Four'][((int(str(scd).split('-')[1]) -1 )//3)]),
                                                                                                                                    ) if self.scar_conf.get('scd') else '',
                    'Milestone Changes'                                 : '',
                    'Source Identifying Control Vulnerability'          : f"{prefix} {req['scan_title']}",
                    'Status'                                            : status,
                    'Comments'                                          : comments,
                    'Raw Severity'                                      : Utils.risk_val(req['severity'], 'MIN'),
                    'Devices Affected'                                  : hosts,
                    'Mitigations'                                       : "Mitigation not required as check is NA." if is_na else mitigation_statement,
                    'Predisposing Conditions'                           : predisposing_conditions,
                    'Severity'                                          : Utils.risk_val(req['severity'], 'POAM'),
                    'Relevance of Threat'                               : relevance,
                    'Threat Description'                                : req['description'],
                    'Likelihood'                                        : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact'                                            : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact Description'                                : impact_statement,
                    'Residual Risk Level'                               : Utils.risk_val(req['severity'], 'POAM'),
                    'Recommendations'                                   : req['solution'],
                    'Resulting Residual Risk after Proposed Mitigations': residual_risk,
                }

                if str(req.get('severity', '')).strip() == '0':
                    continue
                if 'publication_date' not in req:
                    report.append(req_data)
                elif req['publication_date'] is None:
                    report.append(req_data)
                elif( str(req['publication_date']).strip() == '' ):
                    report.append(req_data)
                elif( datetime.datetime.strptime(req['publication_date'],'%Y/%m/%d')  < datetime.datetime.today() - datetime.timedelta(days=self.scar_conf.get('exclude_plugins') ) ):
                    report.append(req_data)

                            
                    
                # pylint: enable=C0330
        print( "        {} - Generating POAM".format(datetime.datetime.now() - start_time) )
        
        #<----Page Header Start---->#
         
        green_header = self.poam_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.poam_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.poam_workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.poam_workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.poam_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        poam_worksheet.merge_range(0, 0, 0, 25, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        poam_worksheet.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        poam_worksheet.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 13):
            poam_worksheet.write(1, col, '', gray_header_cells)
        poam_worksheet.merge_range(1, 13, 1, 25, '', gray_header_merged) 
        
        poam_worksheet.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        poam_worksheet.merge_range(2, 2, 2, 5, '', normal_cell)
        poam_worksheet.write(2, 6, 'Office / Org:', gray_label)
        poam_worksheet.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 13):
            poam_worksheet.write(2, col, '', gray_header_cells)
        poam_worksheet.merge_range(2, 13, 2, 25, '', gray_header_merged) 
        
        poam_worksheet.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        poam_worksheet.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        poam_worksheet.write(3, 6, 'POC Name:', gray_label)
        poam_worksheet.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        poam_worksheet.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        poam_worksheet.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        poam_worksheet.write(3, 12, '', gray_header_cells)
        poam_worksheet.merge_range(3, 13, 3, 25, '', gray_header_merged) 
        
        poam_worksheet.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        poam_worksheet.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        poam_worksheet.write(4, 6, 'POC Phone:', gray_label)
        poam_worksheet.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        poam_worksheet.write(4, 9, 'Reviewed / Updated By:', gray_label)
        poam_worksheet.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        poam_worksheet.write(4, 12, '', gray_header_cells)
        poam_worksheet.merge_range(4, 13, 4, 25, '', gray_header_merged) 
        
        poam_worksheet.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        poam_worksheet.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        poam_worksheet.write(5, 6, 'POC E-Mail:', gray_label)
        poam_worksheet.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 13):
            poam_worksheet.write(5, col, '', gray_header_cells)
        poam_worksheet.merge_range(5, 13, 5, 25, '', gray_header_merged) 
        
        #<----Page Header End---->#
        
        row = 6
        bold = self.poam_workbook.add_format({'bold': True, 'font_size': 12, 'align': 'center', 'valign': 'vcenter', 'text_wrap': True, 'border': 1})
        cell_format = self.poam_workbook.add_format({'font_size': 11, 'text_wrap': True, 'align': 'left', 'valign':'top', 'border': 1})
        date_fmt = self.poam_workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 11, 'align': 'justify', 'valign':'top', 'border': 1})

        if report:
            report = sorted(report, key=lambda s: (
                str(s['Status']).lower().strip(),
                str(s['Source Identifying Control Vulnerability']).lower().strip(),
                str(s['Security Checks']).lower().strip()
            ))
            col = 0
            for column_header in report[0]:
                poam_worksheet.write(row, col, column_header, bold)
                col += 1            
            row += 1
            data_start_row = row

            for result in report:
                col = 0
                for value in result:
                    if col == 7:
                        try:
                            # Try to write as a true Excel datetime object (to apply num_format)
                            poam_worksheet.write_datetime(row, col, result[value], date_fmt)
                        except Exception:
                            # Fallback to writing as string if value is not datetime-compatible
                            poam_worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    else:
                        poam_worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    col += 1
                row += 1
            
            data_end_row = row - 1
                
            # Map Headers to Columns
            header_map = {v: k for k, v in enumerate(report[0].keys())}
            
            # Validation Range mappings
            validations = {
                'Raw Severity': 'RawSeverity',
                'Severity': 'levels',
                'Relevance of Threat': 'levels',
                'Likelihood': 'levels',
                'Impact': 'levels',
                'Residual Risk Level': 'levels',
                # 'Status': 'status'
            }
            
            # Apply data validtion
            for header, named_range in validations.items():
                if header in header_map:
                    col_idx = header_map[header]
                    poam_worksheet.data_validation(
                        data_start_row, col_idx, data_end_row, col_idx,
                        {
                            'validate': 'list',
                            'source': f'={named_range}'
                        }
                    )
                    
        # Create Mitigations Template for this POAM            
        Utils.write_mitigations_csv(report, self.report_dir)
        
        # Create Impacts Template for this POAM            
        Utils.write_impacts_csv(report, self.report_dir)
        
        # Create Resources Template for this POAM            
        Utils.write_resources_csv(report, self.report_dir)
                    
        # Generate Instructions Sheet as last tab
        instruction_sheet = self.poam_workbook.add_worksheet('Instructions')

        instruction_content = [
            "1. This POA&M Template is intended for RMF Systems only. If documenting POA&M Items for a DIACAP System, please download the DIACAP POA&M Template available on the eMASS Help page.",
            "2. Enter valid information into the fields on the POA&M Template.",
            "3. The POA&M Item ID is automatically generated by eMASS after the POA&M Item is successfully imported.  No user action is required to complete or update and therefore this column can be treated as read-only.",
            "4. Do not delete columns/sheets, delete the classification label, or add additional columns. Doing so may have a negative impact on the ability for eMASS to ingest the template.",
            "5. To import a System-level POA&M Item, the Security Control Number field must be left blank.",
            "6. To import a Control-level POA&M Item, enter the appropriate Control Acronym (e.g., AC-3) into the Security Control Number field.",
            "7. To import an Assessment Procedure-level POA&M Item, enter the appropriate AP Acronym (e.g., AC-3.1) into the Security Control Number field.",
            "8. When entering Office/Org, enter Organization, First Name Last Name, Phone Number, Email. At a minimum, the Office/Org must be defined for each POA&M Item. If multiple fields are entered, ensure each field is separated by a comma. Do not separate first and last name with a comma.",
            "9. Security Checks (optional field) can be populated with DISA Security Technical Implementation Guide (STIG) rules (i.e. SV-40098r2_rule), USCYBERCOM IAVM IDs, or ACAS Plugin IDs.",
            "10. When listing multiple Security Checks for a specific POA&M Item, separate each Security Check by a semicolon.",
            "11. If a POA&M Item has multiple milestones, each milestone must be entered in separate rows within the Milestone w/Completion Date field.",
            "12. If a POA&M Item has multiple milestone changes, each milestone change must be entered chronologically in separate rows within the Milestone Changes field.",
            "13. For unapproved POA&M Items, the Milestone Scheduled Completion Date cannot exceed that of the overall Scheduled Completion Date. For POA&M Items that have a Review Status of \"Approved\" in eMASS, a Milestone Scheduled Completion Date can be set beyond that of the overall Scheduled Completion Date to create a pending Extension Date.",
            "14. To add a new milestone to an existing POA&M Item, insert a new row after the last existing milestone for the applicable POA&M. Information entered into that row will be used to populate the new milestone upon import.",
            "15. Dates in the Status (for Completed & AO Approved Risk Accepted POA&M Items), Milestones w/Completion Dates, and Milestone Changes field must be entered after text.",
            "16. Raw Severity (optional field) can be populated with values of I, II, or, III. Raw Severity values are typically defined for vulnerabilities related to DISA STIG Security Checks.",
            "17. Expected values for the optional fields of Severity, Relevance of Threat, Likelihood, Impact, and Residual Risk Level are Very Low, Low, Moderate, High, or Very High.",
            "18. Values for the optional fields of Impact and Residual Risk Level should be reflective of the DoD-defined risk calculation matrixes in Tables 8 and 9 on the RMF Knowledge Service (https://rmfks.osd.mil/rmf/RMFImplementation/AssessControls/Pages/ResidualRisk.aspx).",
            "19. For Ongoing POA&M Items, the Status, Scheduled Completion Date, Office/Organization, Vulnerability Description, and Source Identifying Vulnerability act as required fields. For Completed and Risk Accepted POA&M Items, the Comments field is also required.",
            "20. If updating existing POA&M Item and/or milestone information, ensure that those changes are being applied to the latest version of each POA&M Item. Export the latest copy of applicable POA&M Items via the POA&M Import page in eMASS."
        ]

        bold_format = self.poam_workbook.add_format({'bold': True, 'font_size': 20, 'font_name': 'Times New Roman', 'border': 1})
        normal_format = self.poam_workbook.add_format({'text_wrap': True, 'font_size': 11, 'font_name': 'Calibri'})

        instruction_sheet.write(0, 0, 'POA&M Template Instructions', bold_format)

        for i, line in enumerate(instruction_content, start=2):
            instruction_sheet.write(f"A{i}", line, normal_format)

        instruction_sheet.set_column('A:A', 152)
        print( "        {} - Finished generating POAM".format(datetime.datetime.now() - start_time) )
                        
    def rpt_generate_deviations_workbook(self):
        """Generates a standalone Deviations workbook (CKL/CKLB only)."""
        
        if 'rpt_generate_deviations_workbook' in self.scar_conf.get('skip_reports'):
            return None

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_name = os.path.join(self.report_dir, "Deviations.xlsx")
        self.deviations_workbook = xlsxwriter.Workbook(summary_name)

        # --- Deviations tab (POA&M-like layout/feel) ---
        deviations_ws = self.deviations_workbook.add_worksheet('Deviations')
        deviations_ws.activate()
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Deviations' Workbook")
            QtGui.QGuiApplication.processEvents()

        # Widths intentionally similar to POA&M look/feel (separate workbook)
        widths = [1,20,40,15,25,25,45,25,25,60,30,25,75,40]
        for idx, w in enumerate(widths):
            deviations_ws.set_column(f"{xl_col_to_name(idx)}:{xl_col_to_name(idx)}", w)

        deviations_ws.autofilter(6, 0, 6, len(widths) - 1)

        # --- Load parsed scans ---
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)

        # --- Only CKL/CKLB checklists; project scan_title at req-level (mirrors rpt_poam pattern) ---
        disa_ckls = jmespath.search(
            """results[?type=='CKL' || type=='CKLB'].{
                filename: filename,
                version: version,
                release: release,
                hostname: hostname,
                requirements: requirements[] | [*].{
                    scan_title: title,
                    req_title: req_title,
                    cci: cci,
                    grp_id: grp_id,
                    vuln_id: vuln_id,
                    rule_id: rule_id,
                    plugin_id: plugin_id,
                    status: status,
                    finding_details: finding_details,
                    comments: comments,
                    severity: severity,
                    description: description,
                    solution: solution
                }
            }""",
            {'results': scan_results}
        ) or []

        # Optional mitigation lookups (same behavior you used in your sheet version)
        selected_mitigations = {}
        for mit in self.scar_data.get('mitigations', {}).get('mitigations', []):
            if mit.get('plugin_id', '').strip():
                selected_mitigations[str(mit['plugin_id'])] = mit['mitigation']
            if mit.get('vuln_id', '').strip():
                selected_mitigations[str(mit['vuln_id'])] = mit['mitigation']
            if mit.get('rule_id', '').strip():
                selected_mitigations[str(mit['rule_id'])] = mit['mitigation']

        # Regex for the deviation line inside "Rule Result"
        dev_re = re.compile(
            r"Deviation authorized by '([^']+)' at ([0-9T:\-]+)\s+Reason:\s*'([^']+)'",
            re.IGNORECASE
        )

        # --- Build rows ---
        report_rows = []
        for scan in disa_ckls:
            host = scan.get('hostname', '')
            for req in (scan.get('requirements') or []):
                comments = (req.get('comments') or "").strip()
                if not comments:
                    continue

                m = dev_re.search(comments)
                if not m:
                    continue

                auth_by, ts, reason = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
                scan_title = req.get('scan_title', '')

                rmf_controls = req.get('rmf_controls', '') or \
                    self.scar_data.get('data_mapping', {}).get('ap_mapping', {}).get(req.get('cci', ''), '')

                sev_num  = req.get('severity', '')
                sev_poam = Utils.risk_val(sev_num, 'POAM') if sev_num != '' else ''
                sev_min  = Utils.risk_val(sev_num, 'MIN')  if sev_num != '' else ''

                mitigation_statement = ''
                if self.scar_conf.get('mitigation_statements') == 'poam':
                    if str(req.get('plugin_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['plugin_id'])]
                    if str(req.get('vuln_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['vuln_id'])]
                    if str(req.get('rule_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['rule_id'])]
                elif self.scar_conf.get('mitigation_statements') == 'ckl':
                    mitigation_statement = comments
                elif self.scar_conf.get('mitigation_statements') == 'both':
                    if str(req.get('plugin_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['plugin_id'])]
                    if str(req.get('vuln_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['vuln_id'])]
                    if str(req.get('rule_id','')) in selected_mitigations:
                        mitigation_statement = selected_mitigations[str(req['rule_id'])]
                    if mitigation_statement.strip() == '':
                        mitigation_statement = comments

                row = {
                    'A'                                                 : '',
                    'Deviation Item ID'                                 : '',
                    'Control Vulnerability Description'                 : f"Title: {req.get('req_title','')}\nFamily: {req.get('grp_id','')}\n\nDescription:\n{req.get('description','')}",
                    'Security Control Number (NC/NA controls only)'     : rmf_controls,
                    'Office/Org'                                        : f"{self.scar_data.get('command')}\n{self.scar_data.get('name')}\n{self.scar_data.get('phone')}\n{self.scar_data.get('email')}\n".strip(),
                    'Security Checks'                                   : f"{req.get('plugin_id','')}{req.get('rule_id','')}\n{req.get('vuln_id','')}",
                    'Source Identifying Control Vulnerability'          : f"CKL {scan_title}",
                    'Deviation Authorized By'                           : auth_by,
                    'Deviation Timestamp'                               : ts,
                    'Deviation Reason'                                  : reason,
                    'Comments'                                          : comments,
                    'Raw Severity'                                      : sev_min,
                    'Devices Affected'                                  : host,
                    'Mitigations'                                       : mitigation_statement,
                }
                report_rows.append(row)

        # Sort similar to POA&M’s ordering
        report_rows.sort(key=lambda r: (
            str(r.get('Source Identifying Control Vulnerability','')).lower().strip(),
            str(r.get('Security Checks','')).lower().strip()
        ))
        
        #<----Page Header Start---->#
         
        green_header = self.deviations_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'bg_color': '#007A33',  
            'font_size': 14,
            'font_color': 'white',
            'border': 1
        })
        
        gray_label = self.deviations_workbook.add_format({
            'bold': True,
            'align': 'left',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#BFBFBF',
            'border': 1
        })
        
        normal_cell = self.deviations_workbook.add_format({
            'border': 1,
            'font_size': 12
        })
        
        gray_header_cells = self.deviations_workbook.add_format({
            'bg_color': '#BFBFBF'
        })
        
        gray_header_merged = self.deviations_workbook.add_format({
            'bg_color': '#BFBFBF',
            'right': 1
        })

        deviations_ws.merge_range(0, 0, 0, 13, '***** CONTROLLED UNCLASSIFIED INFORMATION *****', green_header)
        
        deviations_ws.merge_range(1, 0, 1, 1, 'Date Exported:', gray_label)
        deviations_ws.merge_range(1, 2, 1, 5, '', normal_cell)
        for col in range(6, 10):
            deviations_ws.write(1, col, '', gray_header_cells)
        deviations_ws.merge_range(1, 10, 1, 13, '', gray_header_merged) 
        
        deviations_ws.merge_range(2, 0, 2, 1, 'Exported By:', gray_label)
        deviations_ws.merge_range(2, 2, 2, 5, '', normal_cell)
        deviations_ws.write(2, 6, 'Office / Org:', gray_label)
        deviations_ws.merge_range(2, 7, 2, 8, self.office_org, normal_cell)
        for col in range(9, 10):
            deviations_ws.write(2, col, '', gray_header_cells)
        deviations_ws.merge_range(2, 10, 2, 13, '', gray_header_merged) 
        
        deviations_ws.merge_range(3, 0, 3, 1, 'Information System Owner:', gray_label)
        deviations_ws.merge_range(3, 2, 3, 5, self.poc_name, normal_cell)
        deviations_ws.write(3, 6, 'POC Name:', gray_label)
        deviations_ws.merge_range(3, 7, 3, 8, self.poc_name, normal_cell)
        deviations_ws.write(3, 9, 'Date Reviewed / Updated:', gray_label)
        deviations_ws.merge_range(3, 10, 3, 11, self.exported_date, normal_cell)
        deviations_ws.write(3, 12, '', gray_header_cells)
        deviations_ws.write(3, 13, '', gray_header_merged) 
        
        deviations_ws.merge_range(4, 0, 4, 1, 'System Name:', gray_label)
        deviations_ws.merge_range(4, 2, 4, 5, self.systemname, normal_cell)
        deviations_ws.write(4, 6, 'POC Phone:', gray_label)
        deviations_ws.merge_range(4, 7, 4, 8, self.poc_phone, normal_cell)
        deviations_ws.write(4, 9, 'Reviewed / Updated By:', gray_label)
        deviations_ws.merge_range(4, 10, 4, 11, self.reviewed, normal_cell)
        deviations_ws.write(4, 12, '', gray_header_cells)
        deviations_ws.write(4, 13, '', gray_header_merged) 
        
        deviations_ws.merge_range(5, 0, 5, 1, 'APMS ID:', gray_label)
        deviations_ws.merge_range(5, 2, 5, 5, self.apmsid, normal_cell)
        deviations_ws.write(5, 6, 'POC E-Mail:', gray_label)
        deviations_ws.merge_range(5, 7, 5, 8, self.poc_email, normal_cell)
        for col in range(9, 10):
            deviations_ws.write(5, col, '', gray_header_cells)
        deviations_ws.merge_range(5, 10, 5, 13, '', gray_header_merged) 
        
        #<----Page Header End---->#

        # --- Write out ---
        start_row = 6
        bold = self.deviations_workbook.add_format({'bold': True, 'font_size': 12, 'align': 'center', 'valign': 'vcenter', 'text_wrap': True, 'border': 1})
        cell_format = self.deviations_workbook.add_format({'font_size': 11, 'text_wrap': True, 'align': 'left', 'valign':'top', 'border': 1})

        if report_rows:
            headers = list(report_rows[0].keys())
            for col_idx, header in enumerate(headers):
                deviations_ws.write(start_row, col_idx, header, bold)
            r = start_row + 1
            for entry in report_rows:
                for c, k in enumerate(headers):
                    deviations_ws.write(r, c, str(entry.get(k, '')).strip(), cell_format)
                r += 1
                
        self.deviations_workbook.close()
