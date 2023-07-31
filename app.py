import csv
from flask import Flask, render_template, request, jsonify
import time


app = Flask(__name__)

def calculate_risk_score(row):
    
    risk_score = 0
    cvss_score = float(row['CVSS3.0'])
    risk_score += cvss_score * 50

    if row['Network Zone'] == 'public':
        risk_score += 100
    else:
        risk_score -= 50

    exploit_code_maturity_dict = {'non-existent': 0, 'proof-of-concept': 50, 'functional': 100}
    risk_score += exploit_code_maturity_dict[row['Exploit Code Maturity']]

    risk_score += int(row['Dark Web References']) * 0.5

    if row['Patch Available'] == 'yes':
        risk_score -= 100

    if row['Actively Exploited'] == 'yes':
        risk_score += 100

    risk_score = max(0, min(1000, risk_score))

    return risk_score

def calculate_risk_severity(risk_score):
    if risk_score <= 399:
        return 'Low'
    elif risk_score <= 699:
        return 'Medium'
    elif risk_score <= 899:
        return 'High'
    else:
        return 'Critical'

def partition(array, low, high):
    
    i = low - 1
    pivot = array[high]['Risk Score']

    for j in range(low, high):
        if array[j]['Risk Score'] >= pivot:
            i += 1
            array[i], array[j] = array[j], array[i]

    array[i + 1], array[high] = array[high], array[i + 1]
    return i + 1

def quicksort(array, low, high):
    if low < high:
        partition_index = partition(array, low, high)
        quicksort(array, low, partition_index - 1)
        quicksort(array, partition_index + 1, high)

@app.route('/calculate_and_sort', methods=['POST'])
def calculate_and_sort():
    start_time = time.time()

    entries = request.json['entries']
    vulnerabilities = {}
    
    with open(f'vulnerabilities_{entries}.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            guid = row['GUID']
            vulnerabilities[guid] = dict(row)
            vulnerabilities[guid]['Risk Score'] = calculate_risk_score(row)
            vulnerabilities[guid]['Risk Severity'] = calculate_risk_severity(int(vulnerabilities[guid]['Risk Score']))
        
    vulnerabilities_list = list(vulnerabilities.values())
    quicksort(vulnerabilities_list, 0, len(vulnerabilities_list) - 1)

    execution_time = time.time() - start_time
    return jsonify({'data': vulnerabilities_list, 'execution_time': execution_time})


@app.route('/get_raw_data', methods=['POST'])
def get_raw_data():
    entries = request.json['entries']
    filename = 'vulnerabilities_{}.csv'.format(entries)
    try:
        with open(filename, 'r') as file:
            print(f'{filename} file successfully opened.')
            reader = csv.DictReader(file)
            raw_data = []
            for row in reader:
                guid = row.get('GUID', 'N/A')
                name = row.get('Name', 'N/A')
                description = row.get('Description', 'N/A')
                cvss = row.get('CVSS3.0', 'N/A')
                network_zone = row.get('Network Zone', 'N/A')
                exploit_code_maturity = row.get('Exploit Code Maturity', 'N/A')
                actively_exploited = row.get('Actively Exploited', 'N/A')
                patch_available = row.get('Patch Available', 'N/A')
                dark_web_references = row.get('Dark Web References', 'N/A')
                risk_score = row.get('Risk Score', 'N/A')
                risk_severity = row.get('Risk Severity', 'N/A')

                raw_data.append({
                    'GUID': guid,
                    'Name': name,
                    'Description': description,
                    'CVSS3.0': cvss,
                    'Network Zone': network_zone,
                    'Exploit Code Maturity': exploit_code_maturity,
                    'Actively Exploited': actively_exploited,
                    'Patch Available': patch_available,
                    'Dark Web References': dark_web_references,
                    'Risk Score': risk_score,
                    'Risk Severity': risk_severity
                })

            return jsonify(raw_data)
    except IOError as e:
        print(f'Error opening file: {filename}. Error: {str(e)}')
        return jsonify({'error': f'Unable to open file: {filename}'}), 500
    except Exception as e:
        print(f'Unexpected error: {str(e)}')
        return jsonify({'error': 'Unexpected server error'}), 500

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)