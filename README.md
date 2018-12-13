
This script looks up hash from filenames such as virusshare_38bc9f0d841c20d288a3fb3f1b235beb and organizes them

```python
import glob
import requests
import os
from collections import Counter

def getmalwaretypes(hashy):
    params = {'apikey': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx','resource': hashy}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "Python User Agent"
  }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    json_response = response.json()

    #take all scanners and place into list
    scanners=[]
    for x in json_response['scans']:
        scanners.append(x)
    
    #what did each scanner report and place to list
    suggestedmalware=[]
    for x in scanners:
        suggestedmalware.append(json_response['scans'][x]['result'])

    #eliminate NaNs
    malwaretypes = [i for i in suggestedmalware if i is not None]
    return malwaretypes
```


```python

```


```python
#ls *foldername with malware*
execute = os.popen('ls bigpack')
files = execute.read()
#take all file names and make a list 
files = files.split('\n')
#eliminate first list element
files = files[:-1]
```


```python
#make a counter
counter=0

#iterate through each file
for filename in files:
    #take hash of witihin filename
    hashy = filename.split('_')[1]
    #get malware types
    malwaretype = getmalwaretypes(hashy)
    #most reported scan = what the malware is 
    probably = Counter(malwaretype).most_common(1)[0][0]
    #make directory of reported malware
    execute = os.popen('mkdir ' + probably)
    #move it into newlyy made folder
    execute = os.popen('mv bigpack/' + filename + ' ' + probably)
    execute.read()
    counter=counter+1
    print(filename.split('_'), probably, counter)
```


```python

```
