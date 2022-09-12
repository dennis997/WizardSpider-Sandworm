from cgitb import lookup
from enum import Enum
import pandas as pd
import argparse
import json
import glob
import os
import plotly.express as px
import plotly.graph_objects as go

# Forked version of Josh Zelonis's evaluation script for MITRE ATT&CK Evaluations round 4 (Wizard Spider & Sandworm)
# The source code was restructured, commented and adjusted to MSSP Evaluation purposes using different metrics and standards, 
# as well as a different output format and additional plotting capabilities

class EvalMitreResults():
    def __init__(self, filename):                                       
        self._vendor = filename.split(os.sep, -1)
        self._vendor = self._vendor[-1].split('.', 1)[0]            # Splits path string to extract vendor name
        self._sources = {}                                          # Class-level unique list of all data sources
        print(f'Processing {self._vendor}')
        with open(filename, 'r', encoding='utf-8') as infile:
            data=infile.read()

        self._dataset = json.loads(data)                           
        self._adv = None
        self._dataSourceComponentRelation = self.getRelations()     # Fills dataSourceComponentRelation dict for lookups
        self._topFifteenTechniques = ['T1053', 'T1059', 'T1574', 'T1090', 'T1036', 'T1218', 'T1543', 'T1055',
                                      'T1562', 'T1027', 'T1021', 'T1095', 'T1047', 'T1112', 'T1105']
        self._df = pd.DataFrame(columns=('Substep',                         
        'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 
        'SubtechniqueId', 'SubtechniqueName', 'Detection', 'Modifiers', 'DataSource'))

    # Retrieves dictionary of Data Source components across the MITRE knowledge base files to provide lookup functionality
    def getRelations(self):
        dataSourceComponentRelation = {}
        for componentFile in sorted(glob.glob(os.path.dirname(__file__) + '/x-mitre-data-component/*json')):
            with open(componentFile, 'r', encoding='utf-8') as componentFile:                               
                data=componentFile.read()
                componentData = json.loads(data)
                componentName = componentData['objects'][0]['name']
                relatedSourceFile = componentData['objects'][0]['x_mitre_data_source_ref']  # Retrieves related JSON file for association with collectionLayer
                collectionLayers = []
                with open(glob.glob(os.path.dirname(__file__))[0] + f'/x-mitre-data-source/{relatedSourceFile}.json', 'r', encoding='utf-8') as sourceFile:
                    data=sourceFile.read()
                    sourceData = json.loads(data)
                    x = sourceData['objects'][0]
                    collectionLayers = sourceData['objects'][0]['x_mitre_collection_layers']
                    # Writes tuple with datasource and corresponding collectionlayers into dict
                dataSourceComponentRelation.update({componentName : collectionLayers})               
        return dataSourceComponentRelation        

    # Data Collection Layer lookup based on provided component
    def lookUpRelation(self, components):
        self._dataSourceComponentRelation
        dataSources = {}
        for component in components:
            if not component in self._dataSourceComponentRelation:
                continue
            dataSources.update({component : self._dataSourceComponentRelation[component]})
        return dataSources
        
    def getDetection(self, detections):
        ret = {'Detection_Type':'None', 'Modifiers':'', 'Indicator':'', 'Indicator_Name':'', 'Data_Source':''}   # Defines default value "None" as detection type
        dt = Enum('DetectionTypes', 'None Telemetry General Tactic Technique N/A')                               # Assigns integer value 1 to 6 to detection categories
        sev = Enum('Severity', 'Informational Low Medium High Critical')
        components = []                                                                                
        for detection in detections:
            if ("Delayed" in detection['Modifiers'] and len(detection['Modifiers']) <= 1) or not len(detection['Modifiers']): # Detection will be recognized only with "Delayed" Modifier or with none
                for screenshot in detection['Screenshots']:
                    for srcDesc in screenshot['Data_Sources']:
                        componentName = srcDesc.split(": ")                                                      # "Process: Process Creation" --> "Process Creation"
                        [components.append(componentName[1]) if componentName[1] not in components else '']      # Collects the data sources across for every detection                                                 
                if dt[ret['Detection_Type']].value < dt[detection['Detection_Type']].value:                      # Checks for more than one detection and always the best one
                    ret = detection
        dataSources = self.lookUpRelation(components)
        return (ret['Detection_Type'], ret['Modifiers'], dataSources)                                            # Returns tuple of detection information 


    # Append detection info for the substep to dataframe
    # iterSteps returns Substep-object as JSON and calls appendSubstep for every substep for processing the JSON object
    def appendSubstep(self, substep):
        dataset = { 'Substep':None, 'Criteria':None, 'Tactic':None, 'TechniqueId':None, 'TechniqueName':None, 'SubtechniqueId':None, 'SubtechniqueName':None, 'Detection':None, 'Modifiers':None, 'DataSource':None}
        dataset['Substep'] = substep['Substep']
        dataset['Criteria'] = substep['Criteria']
        dataset['Tactic'] = substep['Tactic']['Tactic_Name']
        dataset['TechniqueId'] = substep['Technique']['Technique_Id']
        dataset['TechniqueName'] = substep['Technique']['Technique_Name']
        dataset['SubtechniqueId'] = substep['Subtechnique']['Subtechnique_Id']
        dataset['SubtechniqueName'] = '' if substep['Subtechnique']['Subtechnique_Name'] is None else substep['Subtechnique']['Subtechnique_Name'].split(':')[1][1:]
        (dataset['Detection'], dataset['Modifiers'], dataset['DataSource']) = self.getDetection(substep['Detections'])

        # Saves current Substep with into dataFrame of EvalMitreResults class in _df object
        # "dataset" includes all metadata and detection info
        self._df.loc[len(self._df.index)] = dataset


    # Iterator function to process each substep
    def iterSteps(self):
        for scenario in self._adv['Detections_By_Step']:
            for step in self._adv['Detections_By_Step'][scenario]['Steps']:
                for substep in step['Substeps']:
                    self.appendSubstep(substep)


    # Select adversary to analyze
    def selectAdversary(self, adversary):
        for adversary in self._dataset[0]['Adversaries']:
                self._adv = adversary
                break
        self.iterSteps()

    def scoreProtections(self):
    # Check if detection was made for the substep ID -> If detection was made but no response -> extra mentioning in thesis!#
    # Check for "Blocked" in substeps indicating a break in the attack chain for the AttackChain Break metrics
    # Check how many steps it took until the attack chain was broken -> second metric
        try:
            totalSubsteps = self._adv['Aggregate_Data']['Aggregates']['Total_Substeps']
            maxSubstepScore = 0
            chainBreaks = 0
            subStepScore = 0
            tests = len(self._adv['Protections']['Protection_Tests'])
            responseCount = 0    # Counter for detections made but no response triggered -> Possible indicator for bad SOAR integration
        except KeyError:
            return 'n/a'

        for test in self._adv['Protections']['Protection_Tests']:
            for step in test['Substeps']:
                if step['Technique']['Technique_Id'] in self._topFifteenTechniques:
                    maxSubstepScore += 9
                else:
                    maxSubstepScore += 1
                # Checking for chain break                                                                             
                if step['Protection_Type'] == 'Blocked' and not len(step['Modifiers']):      
                    chainBreaks += 1
                    break            # Breaks loop if one substep in tests is blocked -> Chain break
                detected = ['Tactic', 'Technique']
                 # If detection was made (Tactic or Technique) and not blocked -> increment counter
                if self._df.loc[self._df['Substep'] == step['Substep'], 'Detection'].values[0] in detected and not len(step['Footnotes']):     
                    responseCount += 1
                # Count number of steps until attack is blocked and apply scoring
                # Check if technique is top15 leveraged techniques in ATT&CK Sightingsd                                                                   
                if step['Technique']['Technique_Id'] in self._topFifteenTechniques:   
                    subStepScore += 9             # Score according to weight -> Top15 techniques = 90% of all attacks
                else:
                    subStepScore += 1
        print(f'\n{self._vendor}')
        print(f'chainBreaks: {"{:.2f}".format((chainBreaks/tests)*100)}')
        print(f'responseCount: {"{:.2f}".format((1-(responseCount/totalSubsteps))*100)}')
        print(f'weightedSubStepScore: {"{:.2f}".format((1-(subStepScore/totalSubsteps))*100)}')
        return [int((chainBreaks/tests)*100), int((1-(responseCount/totalSubsteps))*100), int((1-(subStepScore/maxSubstepScore))*100)]

    # Generate performance metrics
    def scoreVendor(self):
        counts = self._df.Detection.value_counts()
        misses = 0
        try:
            misses = counts['None']
        except KeyError:
            try:
                misses += counts['Telemetry']
            except KeyError:
                misses = 0
        try:
            techniques = counts['Technique']
        except KeyError:
            techniques = 0
        try:
            tactic = counts['Tactic']
        except KeyError:
            tactic = 0
        try:
            general = counts['General']
        except KeyError:
            general = 0
        try:
            na = counts['N/A']
        except KeyError:
            na = 0

        substepsDet = len(dataset._df.index) - na                   # no data in a substep due to sensor misplacement etc. does not count
        visibility = substepsDet - misses
        analytics = (techniques + tactic)/visibility                # adjusted to visibility as the denominator
        protections = self.scoreProtections()
        linux = 'yes' if 'Linux Capability' in self._adv['Participant_Capabilities'] else 'no'
        print(f'VisibilityScore: {"{:.2f}".format((visibility/substepsDet)*100)}')
        print(f'AnalyticsScore: {"{:.2f}".format(analytics*100)}')
        return (int((visibility/substepsDet)*100), int((analytics)*100), protections, linux)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Query utility for analyzing the MITRE ATT&CK Evaluations'
    )
    parser.add_argument(
        '--strict-mitre',
        help='Override analysis and stick to raw data',
        default=True,
        action='store_true'
    )

    args = parser.parse_args()

    return args

def plotRadarCharts(data, adv):
    plt_vars = ['visibility', 'efficacy', 'chainBreaks', 'response', 'stepScore']
    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=pd.Series(data.loc[0,plt_vars].values),
        theta=plt_vars,
        name=data.loc[0, 'vendor'].split('-')[0],
    ),
    )

    fig.add_trace(go.Scatterpolar(
        r=pd.Series(data.loc[1,plt_vars].values),
        theta=plt_vars,
        name=data.loc[1, 'vendor'].split('-')[0],
    ))

    fig.add_trace(go.Scatterpolar(
        r=pd.Series(data.loc[2,plt_vars].values),
        theta=plt_vars,
        name=data.loc[2, 'vendor'].split('-')[0],

    ))

    fig.add_trace(go.Scatterpolar(
        r=pd.Series(data.loc[3,plt_vars].values),
        theta=plt_vars,
        name=data.loc[3, 'vendor'].split('-')[0],
    ))

    fig.update_traces(
    line=dict(
        width=5,
        shape='linear',
    ),
    )

    fig.update_layout(
    polar=dict(
        radialaxis=dict(
        visible=True
            )),    
    showlegend=True,
    font_size=18)
    fig.show()

if __name__ == '__main__':
    # Processing ATT&CK Evaluation dataset in dataframe for Wizard Spider & Sandworm
    args = parse_args()
    fname = 'wizard-spider-sandworm-mitre.xlsx'
    dfs = {}
    for infile in sorted(glob.glob(os.path.dirname(__file__) + '/data/wss/*json')):
        dataset = EvalMitreResults(infile)
        dataset.selectAdversary('wizard-spider-sandworm')
        dfs.update({dataset._vendor: dataset})

    writer = pd.ExcelWriter(fname, engine='xlsxwriter')
    results = pd.DataFrame(columns=['vendor', 'visibility', 'efficacy', 'chainBreaks', 'response', 'stepScore', 'linux'])

    # Assessment of dataframe and generating output
    for vendor in dfs.keys():
        (visibility, analytics, protection, linux) = dfs[vendor].scoreVendor()
        results.loc[len(results.index)] = {'vendor':vendor, 'visibility':visibility, 'efficacy':analytics, 'chainBreaks':protection[0], 'response':protection[1], 'stepScore':protection[2],  'linux':linux}
    results.to_excel(writer, sheet_name='Results', index=False)

    # Write out individual vendor tabs
    for vendor in dfs.keys():
        dfs[vendor]._df.to_excel(writer, sheet_name=vendor, index=False, columns=['Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'SubtechniqueName', 'Detection', 'Modifiers', 'DataSource'])
    writer.save()
    print(f'{fname} has been written\n')

    # Star Chart Plotting
    resultsForPlot = results.drop(columns=['linux'])
    resultsForPlot.columns = resultsForPlot.columns.to_series().apply(lambda x: x.strip())
    plotRadarCharts(resultsForPlot, 'Wizard Spider & Sandworm')
    
    # Processing ATT&CK Evaluation dataset in dataframe for Carbanak & Fin7
    args = parse_args()
    fname = 'carbanak-fin7-mitre.xlsx'
    dfs = {}
    for infile in sorted(glob.glob(os.path.dirname(__file__) + '/data/cfin/*json')):
        dataset = EvalMitreResults(infile)
        dataset.selectAdversary('carbanak-fin7')
        dfs.update({dataset._vendor: dataset})

    

    writer = pd.ExcelWriter(fname, engine='xlsxwriter')
    results = pd.DataFrame(columns=['vendor', 'visibility', 'efficacy', 'chainBreaks', 'response', 'stepScore', 'linux'])

    # Assessment of dataframe and generating output
    for vendor in dfs.keys():
        (visibility, analytics, protection, linux) = dfs[vendor].scoreVendor()
        results.loc[len(results.index)] = {'vendor':vendor, 'visibility':visibility, 'efficacy':analytics, 'chainBreaks':protection[0], 'response':protection[1], 'stepScore':protection[2],  'linux':linux}
    results.to_excel(writer, sheet_name='Results', index=False)

    # Write out individual vendor tabs
    for vendor in dfs.keys():
        dfs[vendor]._df.to_excel(writer, sheet_name=vendor, index=False, columns=['Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'SubtechniqueName', 'Detection', 'Modifiers', 'DataSource'])
    writer.save()
    print(f'{fname} has been written\n')

    # Star Chart Plotting
    resultsForPlot = results.drop(columns=['linux'])
    resultsForPlot.columns = resultsForPlot.columns.to_series().apply(lambda x: x.strip())
    plotRadarCharts(resultsForPlot, 'Carbanak & FIN7')
