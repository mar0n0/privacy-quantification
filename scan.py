'''

Script to:
 - Decompile apk
 - Get the public methods for each class in each app(with or without third-party libraries) write them to a file
 - Get permissions from android manifest write them to a file
 - Get PII's from privacy policy and write them to a file

The script is supposed to be runned in the main directory.
Example: python3 scan.py -a ./apks -s ./privacy_quantification -p com.tinder -v 14060055

'''

import os
import csv
import json
import subprocess
import argparse
import xml.etree.ElementTree as ET


# Decompile the APK into a directory
def decompile_apk(dir_path, apk):
    # Package Already decompiled
    if os.path.exists(os.path.join(dir_path, apk)):
        return
    
    apk_name = os.path.join(dir_path, apk + ".apk")
    subprocess.run(["jadx", "-d", os.path.join(dir_path, apk), apk_name],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Search for public methods in the source codes
def get_api_methods(api_classes, apk, dir_path):
    
    # File already exists, skip this phase...
    if os.path.isfile(os.path.join(dir_path, "app_methods.csv")):
        return
    
    app_methods_file = open(os.path.join(dir_path, "app_methods.csv"), "w+", newline='')
    app_methods_writer = csv.writer(app_methods_file, delimiter=';')
    
    list_methods = []    
    sources = os.path.join(dir_path, apk, 'sources')
    
    for root, dirs, files in os.walk(sources):
        for file in files:
            with open(os.path.join(root, file), 'r') as f: # Open each file and read its contents
                contents = f.read()
                for clss in api_classes['classes']: # Iterate Classes
                    if clss["class_name"] in contents: # Check Class Import Statement
                        for public_method in clss["public_methods"]: # Search for public methods
                            if public_method["Name"] in contents: # Search for Method in Source Code
                                if not found_method(list_methods, public_method["Name"]): # If Method not found yet
                                    list_methods.append({"class": clss["class_name"], "method": public_method["Name"]}) # Add to an array to check duplicate
                                    app_methods_writer.writerow([clss["class_name"], public_method["Name"]]) # Write Method in CSV
    return

# Verify if a method is in a list of dict of methods
def found_method(list_methods, method):
    found = 0
    for med in list_methods:
        if method in med.values():
            found = 1
            break
    if found == 0:
        return False
    else:
        return True

# Get the PII's related to the publci methods
def get_api_methods_pii(dir_path, scanner_dir):
    
    # File already exists, skip this phase...
    if os.path.isfile(os.path.join(dir_path, "app_methods_piis.csv")):
        return
    
    app_methods_file = open(os.path.join(dir_path, "app_methods.csv"), 'r', newline='')
    app_methods_file_reader = csv.reader(app_methods_file, delimiter=';')
    
    app_methods_pii = open(os.path.join(dir_path, "app_methods_piis.csv"), "w+", newline='')
    app_methods_pii_writer = csv.writer(app_methods_pii, delimiter=';')
        
    csv_file = open(os.path.join(scanner_dir, 'csv/classes_methods_permissons.csv'), 'r', newline='')
    reader = csv.reader(csv_file, delimiter=';')
    
    rows = []
    for row in reader:
        rows.append(row)

    for method in app_methods_file_reader:
        classe = method[0]
        med = method[1]
        for row in rows:
            if classe == row[1] and med == row[2]:
                app_methods_pii_writer.writerow(row)

# Extract the list of android permissions in AndroidManifest.xml
def get_permissions(dir_path, apk):
    
    # File already exists, skip this phase...
    if os.path.isfile(os.path.join(dir_path, "app_permissions.csv")):
        return
    
    app_permissions_file = open(os.path.join(dir_path, "app_permissions.csv"), "w+", newline='')
    app_permissions_writer = csv.writer(app_permissions_file, delimiter=';')
    
    # Path to the Android manifest file
    apk_am_path = os.path.join(dir_path, apk, 'resources', 'AndroidManifest.xml')
    
    # Parse the XML file
    tree = ET.parse(apk_am_path)
    root = tree.getroot()

    # Find all permission elements in the manifest
    permissions = root.findall(".//uses-permission")

    # Print the names of all the permissions
    for permission in permissions:
        permission = permission.attrib['{http://schemas.android.com/apk/res/android}name']
        if 'android.permission' in permission:
            row_values = [str(permission)]
            app_permissions_writer.writerow(row_values)
    
# Get the list of permissions of the manifest and remvoe the ones already found by the public methods scanner
def get_permissions_pii(dir_path, scanner_dir):

    # File already exists, skip this phase...    
    if os.path.isfile(os.path.join(dir_path, "app_permissions_piis.csv")):
        return
    
    #permissions_list = []
    #permissions_methods = get_permissions_methods(dir_path)

    app_permissions = open(os.path.join(dir_path, "app_permissions.csv"), 'r', newline='')
    app_permissions_reader = csv.reader(app_permissions, delimiter=',')
    
    app_permissions_pii = open(os.path.join(dir_path, "app_permissions_piis.csv"), "w+", newline='')
    app_permissions_pii_writer = csv.writer(app_permissions_pii, delimiter=';')
    
    permissions_csv = open(os.path.join(scanner_dir, 'csv/permissions_piis.csv'), 'r', newline='')
    permissions_csv_reader = csv.reader(permissions_csv, delimiter=';')
    
    rows = []
    for row in permissions_csv_reader:
        rows.append(row)
        
    '''         
    # Search if the permissions in android manifest are already present in public methods found
    for line in app_permissions_reader: 
        temp_line = line[0].split('.')[2]
        if temp_line not in permissions_methods:
            permissions_list.append(temp_line)
    
    final_permissions = []      
    for perm in permissions_list: # Search if the permissions are sensitive
        for row in rows:
            if perm == row[0].split(".")[2] and row not in final_permissions:
                final_permissions.append(row)
    '''
    
    final_permissions = []      
    for perm in app_permissions_reader: # Search if the permissions are sensitive
        for row in rows:
            if perm[0].split(".")[2] == row[0].split(".")[2] and row not in final_permissions:
                final_permissions.append(row)
    
    if len(final_permissions) > 0: # If we have permissions to write
        for permission in final_permissions:
            app_permissions_pii_writer.writerow(permission)
    else: # If not delete the file
        app_permissions_pii.close()
        os.remove(os.path.join(dir_path, "app_permissions_piis.csv"))


# Get permissions from the public methods
def get_permissions_methods(dir_path):
    
    list_permissions = []
    api_methods_permissions_csv = open(os.path.join(dir_path, "app_methods_piis.csv"), 'r', newline='')
    api_methods_permissions_csv_reader = csv.reader(api_methods_permissions_csv, delimiter=';')
    
    for line in api_methods_permissions_csv_reader:
        perms = line[4].split(",")
        for i in range(len(perms)):
            if perms[i] not in list_permissions and perms[i] != '':
                list_permissions.append(perms[i])
    
    return list_permissions

# Get the final score
def calculate_score(dir_path, scanner_dir):

    # GET SCORE
    levels = {
        "Sensitive": 40,
        "Personal": 30,
        "Confidential": 15,
        "Public": 10,
        "Non-personal": 5
    }
    

    '''
    # GET PIIS OF METHODS AND PERMISSIONS
    app_permissions_perm_piis = []
    app_methods_met_piis = []
    

    if os.path.isfile(os.path.join(dir_path, "app_methods_piis.csv")):
        app_methods = open(os.path.join(dir_path, "app_methods_piis.csv"), 'r', newline='')
        app_methods_pii_reader = csv.reader(app_methods, delimiter=';')
        app_methods_met_piis = [[row[2], row[3]] for row in app_methods_pii_reader]
        
    if os.path.isfile(os.path.join(dir_path, "app_permissions_piis.csv")):
        app_permissions = open(os.path.join(dir_path, "app_permissions_piis.csv"), 'r', newline='')
        app_permissions_piis_reader = csv.reader(app_permissions, delimiter=';')
        app_permissions_perm_piis = [[row[0], row[1]] for row in app_permissions_piis_reader]
    '''

    
    
    app_permissions_levels_piis = []
    
    # App Permissions
    if os.path.isfile(os.path.join(dir_path, "app_permissions_piis.csv")):
        app_permissions = open(os.path.join(dir_path, "app_permissions_piis.csv"), 'r', newline='')
        app_permissions_piis_reader = csv.reader(app_permissions, delimiter=';')
        app_permissions_levels_piis = [[row[2], row[1]] for row in app_permissions_piis_reader]
    
    app_permissions_score = 0
    for app_level_permission in app_permissions_levels_piis:
        app_permissions_score += levels.get(app_level_permission[0]) 
    
        
    # Max Permissions    
    max_permissions_piis = open(os.path.join(scanner_dir, 'csv/permissions_piis.csv'), 'r', newline='')
    max_permissions_piis_reader = csv.reader(max_permissions_piis, delimiter=';')
    max_permissions_levels_piis = [[row[2], row[1]] for row in max_permissions_piis_reader]    
    
    max_permissions_score = 0
    for max_level_permission in max_permissions_levels_piis:
        max_permissions_score += levels.get(max_level_permission[0]) 
       
        
    # Permissions Score
    permissions_final_score = round((app_permissions_score / max_permissions_score) * 100)
    
    
    app_methods_levels_piis = []
       
    # App Methods
    if os.path.isfile(os.path.join(dir_path, "app_methods_piis.csv")):
        app_methods = open(os.path.join(dir_path, "app_methods_piis.csv"), 'r', newline='')
        app_methods_pii_reader = csv.reader(app_methods, delimiter=';')
        app_methods_levels_piis = [[row[5], row[3]] for row in app_methods_pii_reader]
  
  
    app_methods_score = 0
    for app_level_methods in app_methods_levels_piis:
        app_methods_score += levels.get(app_level_methods[0]) 
    
    
    # Max Methods
    max_methods = open(os.path.join(scanner_dir, 'csv/classes_methods_permissons.csv'), 'r', newline='')
    max_methods_pii_reader = csv.reader(max_methods, delimiter=';')
    max_methods_levels_piis = [[row[5], row[3]] for row in max_methods_pii_reader]
    
    max_methods_score = 0
    for max_level_methods in max_methods_levels_piis:
        max_methods_score += levels.get(max_level_methods[0]) 
    
    methods_final_score = round((app_methods_score / max_methods_score) * 100)

    #csv_final = levels_piis_permissions_scan + levels_piis_methods_scan
    #app_levels = app_permissions_levels_piis + app_methods_levels_piis
    
    # score = 0
    # for app_level in app_levels:
    #     score += check_for_duplicated_piis(app_level, levels, app_levels)
    #score = round(sum(check_for_duplicated_piis(app_level, levels, app_levels) for app_level in app_levels))
    
    #min_score = 0  
    # max_score = 0
    # for level in csv_final:
    #     max_score += check_for_duplicated_piis(level, levels, csv_final)
    # max_score = round(max_score)
    #max_score = round(sum(check_for_duplicated_piis(level, levels, csv_final) for level in csv_final)) #O maximo score é juntar-mos os csvs das permissoes e classes e calcular o score maximo
    
    
    final_score = 100 - round((permissions_final_score + methods_final_score) / 200 * 100)
    
    print(final_score)
     
       
# Check for duplicated piis
def check_for_duplicated_piis(app_level, levels, app_levels): # Check For duplicated PII's
    try:
        
        score = levels.get(app_level[0])
        pii = app_level[1]
        found = 0
        
        for app_pii in app_levels: 
            for x in pii.split(","):
                for y in app_pii[1].split(","):
                   if x == y:
                        found += 1
                        
        score = score / found              
    
    except Exception as e:
        return str(e)
    
    return score


parser = argparse.ArgumentParser(description='Script To Analyse APK')
parser.add_argument('--scanner', '-s', type=str, help='Scanner Directory')
parser.add_argument('--apks', '-a', type=str, help='APKS Directory')
parser.add_argument('--package', '-p', type=str, help='Package Name')
parser.add_argument('--version', '-v', type=str, help='Package Version')
args = parser.parse_args()

# Print Help Menu
if not args.package and not args.version and not args.dir and not args.apks:
    parser.print_help()
    exit()

package_name = args.package
package_version = args.version
scanner_dir = args.scanner
apks_dir = args.apks

with open(os.path.join(scanner_dir, "json/api_classes.json"), "r") as jsonFile:
    api_classes = json.load(jsonFile)
    
dir_path = os.path.join(apks_dir, "{}/{}/".format(package_name, package_version)) 

decompile_apk(dir_path, package_name)
get_api_methods(api_classes, package_name, dir_path)
get_api_methods_pii(dir_path, scanner_dir)
get_permissions(dir_path, package_name)
get_permissions_pii(dir_path, scanner_dir)
calculate_score(dir_path, scanner_dir)    