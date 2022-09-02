import json
import glob
import os

dataSourceComponentRelation = {}

def getRelation():
    for componentFile in sorted(glob.glob(os.path.dirname(__file__) + '/x-mitre-data-component/*json')):
        with open(componentFile, 'r', encoding='utf-8') as componentFile:
            data=componentFile.read()
            componentData = json.loads(data)
            componentName = componentData['objects'][0]['name']
            relatedSourceFile = componentData['objects'][0]['x_mitre_data_source_ref']
            collectionLayers = []
            with open(glob.glob(os.path.dirname(__file__)) + f'/x-mitre-data-source/{relatedSourceFile}.json', 'r', encoding='utf-8') as sourceFile:
                data=sourceFile.read()
                sourceData = json.loads(data)
                x = sourceData['objects'][0]
                collectionLayers = sourceData['objects'][0]['x_mitre_collection_layers']
            dataSourceComponentRelation.update({componentName : collectionLayers})

getRelation()
