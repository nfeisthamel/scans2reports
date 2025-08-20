# Overview

![Scans To Reports](https://github.com/nfeisthamel/scans2reports/blob/master/screenshots/scans_to_reports.png?raw=true)

The Scans To Reports Generator makes it easy to verify the overall compliance of your systems and to glean useful information about all your assets.  This tool is able to parse Tenable ACAS/Nessus Scans, DISA STIG Checklists, SPAWAR SCAP Compliance Checker XCCDF files, CSV Mitigation Answer Files and Excel POAM/eMASS Exports.  The final reports are also generated in a format that is compatible with eMASS POAM imports and artifact uploads.  These reports make it much easier to clearly see the overall security posture of your program.

This is an updated version of the original project by Robert Weber (CyberSecDef) https://github.com/CyberSecDef/scans2reports. 

This version of scans2reports has updated report generation, scan ingestion handling, parsing logic, and enhanced features. It still generates the original (slightly modified) style of reports for those of you who are used to them, but will now create specific workbooks for the POA&M, Hardware/Software Lists, and Ports Protocols and Services reports. Along with this, it automatically generates answerfiles for dynamically selected vulnerabilities from the POA&M report. Those can be filled in and used in a subsequent parsing run to complete this missing POA&M columns. Additionally, the PPSM report can be automatically completed by utilizing a "Vendor ports" CSV file. This file starts out as a JSON file that can be converted using the included vendorPortsCSVtoJSON.ps1 script, or by just making a compatible CSV file. If you have a system that uses specific ports for specific services, you can input that information along with who talks to who (ip-ip communication lines) and import that durring the parse. 

- Major Changes:
    - Updates:
        - Addition of new Report Header fields
        - Addition of new Tools dirctory and Utilities (Utilities accesable via 'Util' menu)
        - Automatic POA&M standalone worksheet generation
        - Automatic HW/SW standalone worksheet generation
        - Automatic PPSM standalone worksheet generation
        - Automatic creation of dynamically selected impacts, mitigations, and resources CSV files after report run
        - General update of many reports to currently accepted format
        - Addition of unpickle_scan_results.py tool if you want to inspect the scan_results.pkl directly
        - Addition of template files for vendor_ports, impacts, mitigations, and resources CSV files
        - Inclusion of vendorPortsCSVtoJSON.ps1 script
            - Code signed by me for my environment, you can remove the signature and re-sign at your leasure or leave it in.
        - Multiple layers of deduplication for standalone reports, starting in the scan_parser and continuing into the report methods themselves. I made my best attempt to not deduplicate the tabs inside the scans2reports.xlsx file so it can be used as a reference.
    
    - Code Changes:
        - Rework of scan_parser.py to gather more information about the systems scanned
            * XCCDF files (SCAP only content) currently has issues with the parser - 20250820
        - Support for new CKLB checklist files from SCC or eSTIG
            - Support for CKL files maintained
        - scan_parser.py now gets .nessus netstat data for hosts that support it (credentialed). Checks for only 'ESTABLISHED' or 'LISTENING' connections (IPV4 only, non 0.0.0.0 or localhost connections)
        - scan_parser.py automatically detects services running on ports (non 0 ports, non localhost targets, non bad-ip targets) and dynamically injects those plugins into the scan_results.pkl for later use.
        - Added numerous logging lines that log to _internal/scans2reports.log for function visibility.
        - Added numerous debugging options, must be manually uncommented and can generate huge logs if turned on.
        - scan_parser.py automatically strips encoding from .nessus files.
        - Updated "Update CKL" function to support ckl -> ckl, cklb -> cklb, and ckl -> cklb.
        - Added IP and MAC cleaning methods to normalize data for later parsing to scan_utils.py
        - Hostname resolution now uses multiple sources to try and resolve hostnames/fqdns
        - CUI banner for all standalone reports added.
        - scans2reports.py now clears scan_results.pkl and configured report options after each run of "Generate Reports" from memory.
        - Various small updates to methods to improve functionality and helper methods created to break up code.

    - Additions:
        - Option to generate a "Deviations" report for vulnerability deviations
            - Currently relies on SCC 'Deviations' configured durring scan as it checks for specific data in the checklist output.
        - Addition HW/SW Enrichment function to take data from older HW/SW reports and import it into the new format. This also supports updating from the original scans2reports hardware and software sheets, but using the older software sheets is not recomended. This function is heavily reliant on having accurate data in previous reports, and having normalized "Asset Names" to match against. If you do choose to use the earlier software tabs, they must be combined and renamed to just "Software".
            - The function will happily run against just the hardware tab.
            - The function will append any missing assets to the end of the hardware tab.
                - Missing assets are defined as anything that doesnt match "Asset Name" and "Mac Address". This function should support moving IP addresses around without generating duplicates.
            - The function will append missing software to the end of the software report, but this can cause older software to reappear. (If older software is updated, this function will not see that its an update and will append the old version) It will also append software for asset name mismatches (If older hosts are identified by IP only, this will not match unless the newer hosts are also identified by IP, and that IP is the same).
            - *THIS FUNCTION IS VERY SLOW* especially for large files, as every line is checked against every other line.
    
    - Report Updates:
        - All reports that apply
            - '#' column no longer incriments up per eMASS instructions sheet
            - eMASS instructions sheet and hidden sheets added where applicable, along with data validation formulas for matching form/function between eMASS templates and report outputs.
        - POA&M
            - No longer prints expected completion date for "closed" vulnerabilities
            - No longer prints Resources Required, Milestone Changes, Mitigations, or Resulting Residual Risk for "NA" items.
            - Report only lowers risk if a mitigation is filled in for that vulnerability
            - Relevance of threat no longer hardcoded to 'High' and is now calculated based on Severity, Likelihood, and Impact.
            - CCI to Security Control Number mapping updated with NIST 800-53r5 data and current CCI data.
            - Report (standalone only) no longer prints ANY CAT IV items, even if "Skip CAT IV" is unchecked.
        - Software (all)
            - Report now tries to report Vendor, software name, version, and in service date for each "Parent System".
        - Hardware
            - MAC column added
                - If a host is found with multiple MAC addresses, the first one in the list is used AFTER deduplicating hosts with matching MAC's.
            - Hosts CAN have the same hostname 'Asset Name' if they have a different IP address, even if they have MACs that math the multiple mac list. This is expected, and is to allow scanning of "Templated" sites where disperate systems are configured the same.

    
    - Bug Fixes:
        - Corrected 'Source Identifying Control Vulnerability' incorrectly reporting checklist titles.
        - Merge nessus "All Hosts" now works as expected.
