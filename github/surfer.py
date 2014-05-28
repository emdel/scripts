#
# surfer.py - It looks for the query and then surf all 
# the matched repositories. It should create a good repository
# of goodware. Thanks Github guys for the APIs :)
#
# Mariano `emdel` Graziano.
#

import sys, requests, json



if len(sys.argv) != 2:
    print "Usage: %s %s" % (sys.argv[0], "query")
    sys.exit(-1)



### GITHUB PARAM ###
URL = 'https://api.github.com/'
USER = 'user'
PASS = 'pass'

headerz = {'User-Agent': 'user', 'Accept': 'application/vnd.github.preview'}


QUERY = sys.argv[1]
SURF = URL + "search/code?" + QUERY
print ":: URL: %s" % SURF
r = requests.get(SURF, auth=(USER, PASS), headers=headerz)
print r.status_code
results = json.loads(r.text)


print ":: Found: %d" % results['total_count']
for ke in results['items']:
    print "\n:: File: %s" % ke['name']
    print "\t -=> path: %s" % ke['path']
    print "\t -=> sha: %s" % ke['sha']
    print "\t -=> url: %s" % ke['url']
    print "\t -=> html_url: %s" % ke['html_url']

    r = requests.get(ke['html_url'].replace('blob', 'raw')) 
    fs = open(ke['sha']+'_'+ke['name'], "wb")
    for chunk in r.iter_content():
        fs.write(chunk)
    fs.close()

