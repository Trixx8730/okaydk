import requests,json,time,random,string,threading
from faker import Faker
fake = Faker()


def getproxy():
	w = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=yes&anonymity=all&simplified=true')
	ok = (w.text).split('\n')[:100]
	random.shuffle(ok)
	head = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0'
	}
	for io in ok:
		prox = (io).replace('\r','').split(':')
		postt = {'ip_addr':f'{prox[0]}','port':f'{prox[1]}'}
		w = requests.post('https://onlinechecker.proxyscrape.com/index.php',headers=head,data=postt)
		print(w.text)
		if w.json()['working'] == True:
			print('STEP2')
			try:
				prox = {'https': f'https://{prox[0]}:{prox[1]}'}
				r = requests.get('https://api.myip.com', proxies=prox,timeout=10)
				if r.status_code == 200:
					print('good one')
					print(prox['https'])
					global httpprox
					httpprox = prox['https']
					break
			except:
				continue
			print('hi')

def dotask():
	username = ''.join([random.choice( string.ascii_lowercase + string.digits) for n in range(11)])
	print('Username:',username)
	head = {
	'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
	'content-type': 'application/json',
	'accept': 'accept: application/json, text/plain, */*'}
	w= requests.post('https://api.mail.tm/accounts',headers=head,json={'address': f"{username}@affecting.org", 'password': "NyqjYaVO"})

	m= requests.post('https://api.mail.tm/authentication_token',headers=head,json={'address': f"{username}@affecting.org", 'password': "NyqjYaVO"})

	print('[+] Email Created!')
	bear = m.json()['token']

	pheaders = {'Authorization': 'Bearer null',
	'timezone': 'Asia/Kolkata',
	'app_ver': '7.5',
	'device-type': 'android',
	'package_name': 'com.squats.fittr',
	'device_udid': 'null',
	'app_certificate_value': 'mg/eawEUzE+Ve6v4u+xpErmMjoOpsNyIEtir/PeJrX8=',
	'Content-Type': 'application/json',
	'app_code': '113',
	'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; SM-J701F Build/PPR1.180610.011)',
	'Host': 'fittr-api.squats.in',
	'Connection': 'Keep-Alive',
	'Accept-Encoding': 'gzip'}
	
	ppost = {"user_obj":{"country_code":"+1","password":"828383737","app_version":"113","phone":f"+1{random.randint(1000000000,9999999999)}","device_token":"null","name":f"{fake.name()}","package_name":"com.squats.fittr","device_type":"android","device_udid":"null","app_certificate_value":"jEobmEz2OdJ2jTywh47DedNoHRAYLAg3mQk+oEvRJFw=","email":f"{username}@affecting.org","country_id":"230"}}
	#http://api.scraperapi.com/?api_key=6757c776866e6d1d75edcc049aeed7b1&url=
	prox = {
	 'https': f'{httpprox}',
	}
	p = requests.post('https://fittr-api.squats.in/v7/client/signup',headers=pheaders,json=ppost,proxies=prox)
	if 'OTP limit' in p.text:
		exit()
	elif 'successfully created' in p.text:
		print('[+] Fittr account Created')
	tokks = {"type":"email","user_id":f"{p.json()['result']['data']['user_id']}"}
	
	
	h = requests.post('https://fittr-api.squats.in/v7/client/resendotp',headers=pheaders,json=tokks)
	print('[+] OTP sent on Email.')
	
	time.sleep(25)
	ohead = {'authorization': f'Bearer {bear}'}
	
	
	o = requests.get('https://api.mail.tm/messages',headers=ohead)
	if 'ACCOUNT CREATED SUCCESSFULLY Hi' in o.text:
		print('[+] Reading OTP')
	
	lenk = o.json()['hydra:member'][0]['@id']
	
	o = requests.get(f'https://api.mail.tm{lenk}',headers=ohead)
	otps= o.json()['text'].split('Verification Code: ')[1][0:4]	
	
	wpost = json.loads(r'{"app_version":"113","device_token":null,"referral_code":"SHUVKWI4","package_name":"com.squats.fittr","verify_through":"2","otp":"5410","device_type":"android","device_udid":null,"app_certificate_value":"4g6dvk2tUFytPLjzzj4XbpHLinodsHIDgROv9UvTtSE=\n","email":"zrk8071@affecting.org"}')
	wpost['email']= (f'{username}@affecting.org')
	wpost['otp']= otps
	w = requests.post('https://fittr-api.squats.in/v7/client/verifyotp',headers=pheaders,json=wpost)
	if 'OTP is verified.' in w.text:
		print('[+] OTP Successfully verified.')
	else:
		print('[+] OTP error.')



if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    getproxy()
    threads = list()
    for index in range(11):
        x = threading.Thread(target=dotask, args=())
        threads.append(x)
        x.start()

    for index, thread in enumerate(threads):
        thread.join()
