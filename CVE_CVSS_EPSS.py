import requests
import csv
import os
import time
import datetime
import math
os.system('cls')
timeStart=datetime.datetime.now()
print("Stating script at " + timeStart.strftime("%d/%m/%Y %H:%M:%S")) #Stating script at 04/03/2025 09:03:54


# Veut dresser la liste de toutes les CVE, leur score CVSS associé, et chercher le score EPSS de celles qui nous intéressent (CVSS entre 4 et 8.9 puis CVSS > 9)
# Liste des CVE : https://github.com/CVEProject/cvelistV5/releases
# Liste des EPSS : https://www.first.org/epss/data_stats
# API pour le score CVSS : https://services.nvd.nist.gov/rest/json/cves/2.0 (5 appels API toutes les 30 secondes MAX)
# API pour le score EPSS : https://api.first.org/data/v1/epss



# Appel API NIST pour savoir le nombre de CVE
def funcNbCVEglobal() :
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    time.sleep(7)
    return nbCVEglobal


# Appel API NIST pour savoir le nombre de CVE en fonction d'un niveau de severity
def funcNbCVEseverity(paramCVSS) :
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0&" + paramCVSS
    reponse = requeteCustom(requete)
    data = reponse.json()
    nbCVEparam = data["totalResults"]
    time.sleep(7)
    return nbCVEparam


# Calcul du nombre de toutes les CVE concernées par au moins un niveau de severité (>= MEDIUM) et une version du CVSS (V2 ou V3)
def calculNbCVEGlobal () :
    nbCVEseverityCVSS2Medium = funcNbCVEseverity(paramCVSS = 'cvssV2Severity=MEDIUM')
    print("Le nombre de CVE CVSS2Medium est actuellement : ", nbCVEseverityCVSS2Medium) # le 17/10/2024 : 104167
    nbCVEseverityCVSS2High = funcNbCVEseverity(paramCVSS = 'cvssV2Severity=HIGH')
    print("Le nombre de CVE CVSS2High est actuellement : ", nbCVEseverityCVSS2High) # le 17/10/2024 : 56836
    nbCVEseverityCVSS3Medium = funcNbCVEseverity(paramCVSS = 'cvssV3Severity=MEDIUM')
    print("Le nombre de CVE CVSS3Medium est actuellement : ", nbCVEseverityCVSS3Medium) # le 18/10/2024 : 67438 | le 05/02/2025 : 70672 | le 04/03/2025 : 71996
    nbCVEseverityCVSS3High = funcNbCVEseverity(paramCVSS = 'cvssV3Severity=HIGH')
    print("Le nombre de CVE CVSS3High est actuellement : ", nbCVEseverityCVSS3High) # le 18/10/2024 : 67069 | le 05/02/2025 : 68188 | le 04/03/2025 : 69007
    nbCVEseverityCVSS3Critical = funcNbCVEseverity(paramCVSS = 'cvssV3Severity=CRITICAL')
    print("Le nombre de CVE CVSS3Critical est actuellement : ", nbCVEseverityCVSS3Critical) # le 18/10/2024 : 24669 | le 05/02/2025 : 25201 | le 04/03/2025 : 25607
    nbCVEglobal = nbCVEseverityCVSS2Medium + nbCVEseverityCVSS2High + nbCVEseverityCVSS3Medium + nbCVEseverityCVSS3High + nbCVEseverityCVSS3Critical
    print('nbCVEglobal = ', nbCVEglobal)
    return nbCVEseverityCVSS2Medium, nbCVEseverityCVSS2High, nbCVEseverityCVSS3Medium, nbCVEseverityCVSS3High, nbCVEseverityCVSS3Critical, nbCVEglobal


# Appel API NIST pour avoir les infos sur les CVE données dans l'URL (entre l'index et le nombre max de résultats) & ecrire dans CVE_CVSS_EPSS_table
def funcDataNIST(offset,paramCVSS) :
    requeteCVE = https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage= + str(offset[0]) + "&startIndex=" + str(offset[1]) + '&' + paramCVSS
    print(requeteCVE)
    reponse = requeteCustom(requeteCVE)
    data = reponse.json()
    for i in range(len(data["vulnerabilities"])):
        CVEtableUnit = {'CVE':'', 'CVSS':'', 'CVSS version':''}
        CVEtableUnit['CVE'] = data["vulnerabilities"][i]["cve"]["id"] # on ajoute l'ID de la CVE
        CVEtableUnit['CVSS version'] = decoderParam(paramCVSS,metrics=data["vulnerabilities"][i]["cve"]["metrics"]) # on ajoute la version du score
        CVEtableUnit['CVSS'] = data["vulnerabilities"][i]["cve"]["metrics"][CVEtableUnit['CVSS version']][0]["cvssData"]["baseScore"] # on ajoute la Métrique CVSS
        #print(CVEtableUnit.values())

        doublon = False
        for l in range(len(CVE_CVSS_EPSS_table)): # Pour eviter les doublons on ne garde que les nouvelles valeurs d'ID de CVE
            if CVE_CVSS_EPSS_table[l]['CVE'] == CVEtableUnit['CVE'] :
                doublon = True
                print('Doublon', CVEtableUnit['CVE'])
                break
        
        if doublon == False :
            # On ajoute les valeurs qui nous intéressent
            CVE_CVSS_EPSS_table.append(CVEtableUnit) # on ajoute nos trois données dans la table
        
    #print(CVE_CVSS_EPSS_table)


# Fonction pour récupérer dans les metrics du Nist, celle correspondant à la version du CVSS demandée
def decoderParam(paramCVSS,metrics) :
    cvssVersionString = paramCVSS[0:6] # On ne garde que les 6 premier caractères de paramCVSS
    if cvssVersionString == 'cvssV2' :
        metricsName = 'cvssMetricV2'
    else :
        listeMetricsName = [c for c in metrics.keys()]
        for k in range(len(listeMetricsName)) :
            if listeMetricsName[k] == 'cvssMetricV31' :
                metricsName = 'cvssMetricV31'
                break
            elif listeMetricsName[k] == 'cvssMetricV30' :
                metricsName = 'cvssMetricV30'
    return metricsName


# Fonction pour incrémenter funcDataNIST
def incrementationDataNIST (offset,nbCVE,paramCVSS) :
    i = 0 # variable pour dérouler les requetes à l'API NIST
    j = 1 # variable pour débuger le nb de requetes
    nbReq = (math.ceil(nbCVE/offset[0])) # nombre de requêtes à faire dans cette incrémentation
    while i < nbCVE : # tant que l'on a pas fait le tour de toutes les CVE indiqué par nbCVEglobal
        if i+offset[0] < nbCVE :
            offset[1] = i # index de départ
            print("Requête n°", j,"sur", str(nbReq), "pour", paramCVSS)
            funcDataNIST(offset,paramCVSS)
            j = j + 1
            i = i + offset[0]
        else :
            offset[0] = nbCVE-i # nombre de résultats que l'on veut pour la dernière requête
            offset[1] = i # index final
            print("Requête n°", j,"sur", str(nbReq), "pour", paramCVSS)
            funcDataNIST(offset,paramCVSS)
            j = j + 1
            i = i + offset[0]
    print('=========== Fin des requêtes pour', paramCVSS)


# Exploitation de la requête sur l'API EPSS attention : limit ~ 100, de plus l'API rend les EPSS dans l'ordre inverse de la requête (filo / lifo)
def constructionRequeteEPSS(debut,fin): #fonction qui permet de créer une requete API avec les CVE allant de début à fin
    ListeCVE = []
    for n in range(fin-debut) :
        ListeCVE.append(CVE_CVSS_EPSS_table[debut+n]['CVE'])
    while True :
        try :
            requeteEPSS = "https://api.first.org/data/v1/epss?cve=+" +",".join(ListeCVE)
            break
        except :
            time.sleep(10)
            continue
    #print(requeteEPSS)
    return requeteEPSS


# fonction pour remplir la liste des EPSS associés aux CVE
def remplissageEPSS():
    i=0
    while i < len(CVE_CVSS_EPSS_table):
        if i+95<len(CVE_CVSS_EPSS_table):
            reponseEPSS = requests.get(constructionRequeteEPSS(debut=i,fin=i+95))
            print("récupération des EPSS jusqu'à la CVE ",str(i+95))
            donneesGlobales = reponseEPSS.json()
            EPSStable = donneesGlobales.get("data")
            
            for o in range(len(EPSStable)):
                for p in range(len(EPSStable)):
                    if CVE_CVSS_EPSS_table[i+o]['CVE'] == EPSStable[p]['cve'] :
                        CVE_CVSS_EPSS_table[i+o]['EPSS'] = EPSStable[p]['epss']
                        CVE_CVSS_EPSS_table[i+o]['EPSS percentile'] = EPSStable[p]['percentile']
                        break
            i = i + 95
            
        else:
            reponseEPSS = requests.get(constructionRequeteEPSS(debut=i,fin=len(CVE_CVSS_EPSS_table)))
            print("récupération des EPSS jusqu'à la CVE ",str(len(CVE_CVSS_EPSS_table)))
            donneesGlobales = reponseEPSS.json()
            EPSStable = donneesGlobales.get("data")

            for o in range(len(EPSStable)):
                for p in range(len(EPSStable)):
                    if CVE_CVSS_EPSS_table[i+o]['CVE'] == EPSStable[p]['cve'] :
                        CVE_CVSS_EPSS_table[i+o]['EPSS'] = EPSStable[p]['epss']
                        CVE_CVSS_EPSS_table[i+o]['EPSS percentile'] = EPSStable[p]['percentile']
                        break
            

            i = (len(CVE_CVSS_EPSS_table))

# effectuer une requete (résistif aux restrictions du NIST)
def requeteCustom(requete):
    compteurException = 0
    while True :
        try :
            reponse = requests.get(requete, timeout=3600)
            print (reponse.status_code)
            if reponse.status_code > 399 :
                compteurException = compteurException + 1
                print("Exception n°", compteurException)
                if compteurException > 10 :
                    time.sleep(20)
                    continue
                else :
                    time.sleep(6)
                    continue
            else :
                time.sleep(6)
                break
        except :
            time.sleep(6)
            compteurException = compteurException + 1
            print("Exception n°", compteurException)
            if compteurException > 10 :
                time.sleep(20)
                continue
            else :
                continue
    return reponse

### MAIN avec les 2 grosses boucles (CVE & CVSS) puis (EPSS)

# On calcule le nombre total de CVE global de base : 
nbCVEseverityCVSS2Medium, nbCVEseverityCVSS2High, nbCVEseverityCVSS3Medium, nbCVEseverityCVSS3High, nbCVEseverityCVSS3Critical, nbCVEglobal = calculNbCVEGlobal()
#nbCVEseverityCVSS2Medium, nbCVEseverityCVSS2High, nbCVEseverityCVSS3Medium, nbCVEseverityCVSS3High, nbCVEseverityCVSS3Critical = 115, 4, 6, 12, 16
#nbCVEglobal = nbCVEseverityCVSS2Medium + nbCVEseverityCVSS2High + nbCVEseverityCVSS3Medium + nbCVEseverityCVSS3High + nbCVEseverityCVSS3Critical
#print(nbCVEseverityCVSS2Medium, nbCVEseverityCVSS2High, nbCVEseverityCVSS3Medium, nbCVEseverityCVSS3High, nbCVEseverityCVSS3Critical, nbCVEglobal)

# NIST (CVE & CVSS)
CVE_CVSS_EPSS_table = []
offsetGlobal = [2000,0] # tableau des offset avec le nombre de résultats que l'on veut par requête et l'index de départ fixé à 0
print("Prêt pour le lancement de", (math.ceil(nbCVEseverityCVSS2Medium/offsetGlobal[0])+math.ceil(nbCVEseverityCVSS2High/offsetGlobal[0])+math.ceil(nbCVEseverityCVSS3Medium/offsetGlobal[0])+math.ceil(nbCVEseverityCVSS3High/offsetGlobal[0])+math.ceil(nbCVEseverityCVSS3Critical/offsetGlobal[0])), "requêtes à l'API du NIST")

# On appelle le NIST de la plus récente version de CVSS à la sévérité la plus haute, à la moins récente version de CVSS, à la sévérité la moins haute (et on écrase pas les id de CVE pour ne pas avoir de doublons)
incrementationDataNIST(offset = [2000,0],  nbCVE = nbCVEseverityCVSS3Critical, paramCVSS='cvssV3Severity=CRITICAL')
fichier = open("CVE_CVSS_table_CV3CRI.txt", "w")
fichier.write(str(CVE_CVSS_EPSS_table))
fichier.close()
incrementationDataNIST(offset = [2000,0],  nbCVE = nbCVEseverityCVSS3High,     paramCVSS='cvssV3Severity=HIGH')
fichier = open("CVE_CVSS_table_CV3HIG.txt", "w")
fichier.write(str(CVE_CVSS_EPSS_table))
fichier.close()
incrementationDataNIST(offset = [2000,0],  nbCVE = nbCVEseverityCVSS3Medium,   paramCVSS='cvssV3Severity=MEDIUM')
fichier = open("CVE_CVSS_table_CV3MED.txt", "w")
fichier.write(str(CVE_CVSS_EPSS_table))
fichier.close()
incrementationDataNIST(offset = [2000,0],  nbCVE = nbCVEseverityCVSS2High,     paramCVSS='cvssV2Severity=HIGH')
fichier = open("CVE_CVSS_table_CV2HIG.txt", "w")
fichier.write(str(CVE_CVSS_EPSS_table))
fichier.close()
incrementationDataNIST(offset = [2000,0],  nbCVE = nbCVEseverityCVSS2Medium,   paramCVSS='cvssV2Severity=MEDIUM')
fichier = open("CVE_CVSS_table_CV2MED.txt", "w")
fichier.write(str(CVE_CVSS_EPSS_table))
fichier.close()

#print(CVE_CVSS_EPSS_table)
print("Nombre de CVE", len(CVE_CVSS_EPSS_table))
print("Nombre de doublons", nbCVEglobal-len(CVE_CVSS_EPSS_table))


# FIRST (EPSS)
print("ok pour l'extraction des EPSS")
remplissageEPSS()

#print(CVE_CVSS_EPSS_table)


### Fichier final
with open('./CVSS_EPSS_Global_List/Global_List.csv', mode="w", newline='') as csvfileFinal:
    headers = ['CVE', 'CVSS', 'CVSS version', 'EPSS', 'EPSS percentile']
    writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
    writer.writeheader()
    writer.writerows(CVE_CVSS_EPSS_table)

timeEnd=datetime.datetime.now()
print("Ending script at " + timeEnd.strftime("%d/%m/%Y %H:%M:%S"))
difftime = (timeEnd - timeStart)
print("Script duration = " + str(difftime))
