# -*- coding: utf-8 -*-

import re
import urllib3
import requests
#from string import strip
from string import *
import dataset
import datetime
import json
import sys
import tweepy
from pymisp import MISPEvent, ExpandedPyMISP, PyMISP, PyMISPError
from urllib3.exceptions import ProtocolError
from logger import LOGGER as l
from config import CONSUMER_KEY, CONSUMER_SECRET, ACCESS_KEY, ACCESS_SECRET, MISP_TOKEN_ACCESS, MISP_URL

def run(**kwargs):
#############################
     def add_tweet_atributes (event, f, fverbose):
     

    
     #md5
        md5_strings = re.findall(r"([\W|:])([a-fA-F\d]{32})(\W|$)", f)  
        
        for md5_string in md5_strings:
           if fverbose:
              l.info("## This is a md5: {} ## ".format(str.rstrip(str.lstrip(md5_string[1]))))
     
           event.add_attribute(type='md5', value=md5_string[1], category='External analysis', to_ids= False)
     #sha1
        sha1_strings = re.findall(r"([\W|:])([a-fA-F\d]{40})(\W|$)", f)   
        
        for sha1_string in sha1_strings:
           if fverbose:
              l.info("## This is a sha1: {} ## ".format(str.rstrip(str.lstrip(sha1_string[1]))))
           event.add_attribute(type='sha1', value=sha1_string[1], category='External analysis', to_ids= False)
     
     #sha256
        sha256_strings = re.findall(r"([\W|:])([a-fA-F\d]{64})(\W|$)", f)   
        
        for sha256_string in sha256_strings:
           if fverbose:
              l.info("## This is a sha1256 {} ## ".format(str.rstrip(str.lstrip(sha256_string[1]))))
           event.add_attribute(type='sha256', value=sha256_string[1], category='External analysis', to_ids= False)
      
     #email
        correo_strings = re.findall(r"([a-z0-9_\.-]+@[\da-z\.-]+\.[a-z\.]{2,6})", f)  
        for correo_string in correo_strings:
           if fverbose:
              l.info("## This is a  sender {} ## ".format(str.rstrip(str.lstrip(correo_string))))
    
           event.add_attribute(type='email-src', value=correo_string, category='External analysis', to_ids= False)
       
     #domain      
        #Se admite que en el nombre de host pueda contener un - pero no se adminte en el tld   
        dominio_strings = re.findall(r"[\da-z\.-]+\.[a-z\.]{2,6}", f)  
        for dominio_string in dominio_strings:
           if fverbose:
              l.info("## Esto es un dominio {} ## ".format(str.rstrip(str.lstrip(dominio_string))))
     
           #event.add_attribute('domain', dominio_string)
           event.add_attribute(type='domain', value=dominio_string, category='External analysis', to_ids= False)
        
     #url  
        #url_strings = re.findall(#r"(\Whttp[s]?:\/\/[\da-z\.-]+\.[a-z\.]{2,6}(:[0-9]{1,5})?[\/][\/\w\S\.-]*\W)", f) 
        #Por sencillez admite como URL todo lo que empieza por http://dominio:puerto o https://dominio:puerto
        url_strings = re.findall(r"(h[t|x][t|x]p[s]?:\/\/[\da-z\.-]+\.[a-z\.]{2,6}(:[0-9]{1,5})?[\/]*[\S]*)", f)
         
        for url_string in url_strings:
   
                
           #Resuleve el dominio caso de estar acortado, además no pregunta al dominio malicioso al no seguir redirecciones
           if fverbose:
              l.info("## Esto es una URL {} ## ".format(str.rstrip(str.lstrip(url_string[0]))))
           if "//t.co/" in url_string[0]:
              #El dominio es acortado y lo expando
              try: 
                r = requests.get(url_string[0], allow_redirects=False)
                event.add_attribute(type='url', value=r.headers['Location'], category='External analysis', to_ids= False)
              except:
                continue
              if fverbose:
                  l.info("## Esto es una URL acortada {} y esta es la original {} ## ".format(str.rstrip(str.lstrip(url_string[0])), r.headers['Location']))
     
           else:
              if fverbose:
                 l.info("## Esto es una URL no acortada {} ## ".format(str.rstrip(str.lstrip(url_string[0]))))
              event.add_attribute(type='url', value=url_string[0], category='External analysis', to_ids= False)
              
             #El dominio no es acortado
     
           
     #IPv4
        ipv4_strings = re.findall(r"(\W((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\W)", f) 
        
        for ipv4_string in ipv4_strings:
           if fverbose:
              l.info("## Esto es una IPv4 {} ## ".format(str.rstrip(str.lstrip(ipv4_string[0]))))
      
           #event.add_attribute('ip-dst', ipv4_string[0])
           event.add_attribute(type='ip-dst', value=ipv4_string[0], category='External analysis', to_ids= False)
        
     #IPv6
        
        ipv6_strings = re.findall(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",f)
        for ipv6_string in ipv6_strings:
           if fverbose:
              l.info("## Esto es una IPv6 {} ## ".format(str.rstrip(str.lstrip(ipv6_string[0]))))
      
           #event.add_attribute('ip-dst', ipv6_string[0])
           event.add_attribute(type='ip-dst', value=ipv6_string[0], category='External analysis', to_ids= False)
     
     #CVE
     #   cve_strings = re.findall(r"(\WCVE-[0-9]{4}-[0-9]{4,7})",f)
     #   
     #   for cve_string in cve_strings:
     #      #print ("##" + str.rstrip(str.lstrip(cve_string)) + "##"+ " Esto es un CVE")
     #      #print (cve_string)
     #      event.add_attribute('cve', cve_string)
     
     #mac-address  
        mac_strings = re.findall (r"(([0-9a-fA-F][0-9a-fA-F][:-]){5}([0-9a-fA-F][0-9a-fA-F]))",f)
        
        for mac_string in mac_strings:
           if fverbose:
              l.info("## Esto es una mac-address {} ## ".format(str.rstrip(str.lstrip(mac_string[0]))))
           event.add_attribute(type='mac-address', value=format(str.rstrip(str.lstrip(mac_string[0]))), category='External analysis', to_ids= False)
      
     
     #############################
 
     def inserta_misp (nombre_evento, full_tweet, fverbose):
                 #Instancio evento MISP
                 event = MISPEvent()
      
                 #Nombre del evento. Se cambiara por cada tweet recibido	
                 event.info = nombre_evento  # Required
                 #Valores por defecto 
      
                 event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
                 event.threat_level_id = 2  # Optional, defaults to MISP.default_event_threat_level in MISP config
                 event.analysis = 1  # Optional, defaults to 0 (initial analysis)	
                 
                 #Inserto el tweet completo
                 #event.add_attribute('External analysis', full_tweet)
                 event.add_attribute('text', full_tweet)
                 
                 event.add_tag('tlp:white')
                 
                 add_tweet_atributes (event, full_tweet, fverbose)
                             
                 #Inserto el evento MISP
                 event = misp.add_event(event, pythonify=True)


     class StreamListener(tweepy.StreamListener):
     
         def __init__(self, api=None, verbose=False):
             super(StreamListener, self).__init__()
             self.verbose = verbose
             self.tweet_list = []
             self.start = datetime.datetime.utcnow()
     
         def on_status(self, status):
             #self.tweet_list.append(status) 
             # Este try hace falta para caso de ser un tweet extendido (mas de 140 caracteres) 
             # http://docs.tweepy.org/en/latest/extended_tweets.html
             if self.verbose:
                l.info ('@@@@@@@@@@@@ Truncated: '+ str(status.truncated) + ' @@@@@@@@@@@@ ')
             if hasattr(status,"extended_tweet"):
                 if self.verbose: 
                     l.info ('@@@@@@@@@@@@ Usa extended_tweet @@@@@@@@@@@@ ')
                 text = status.extended_tweet["full_text"]
             else: 
                 text = status.text
             
   
             #https://stackoverflow.com/questions/43298113/append-tweets-media-expanded-links-quotes-to-the-tweet-text-using-tweepy
             #Quitar acortadores de URL
     
             #http://docs.tweepy.org/en/latest/extended_tweets.html#streaming
             #print (status.entities['urls'])
     
             if 'urls' in status.entities:
                for url in status.entities['urls']:
                   link = url['expanded_url']
                   text = text + ' '+ link  
                   if self.verbose:
                       l.info("## links: {}".format(link))
     
             if self.verbose:
                 l.info ("## status.id, text, status.user.screen_name")
                 l.info("## {}||{}||{}".format(status.id, text, status.user.screen_name))
     
             #Inserta en MISP
             fverbose = self.verbose
             inserta_misp (status.user.screen_name, text, fverbose)
     
         def reset(self):
             self.tweet_list = []
             self.start = datetime.datetime.utcnow()
     
         def on_error(self, status_code):
             l.warn("Error {}".format(status_code))
             
     class MyException(Exception):
        #l.info (Exception)
        pass
         
# Conexión con Twitter

     l.info ("## Estableciendo conexion TWITTER")
     auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
     auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)
     api = tweepy.API(auth)
     stream_listener = StreamListener(verbose=kwargs["verbose"])
     #tweet_mode="extended"
     stream = tweepy.Stream(auth=api.auth, listener=stream_listener, tweet_mode="extended")
     l.info ("## Conexion TWITTER establecida")

# Escribe la información de un tweet por id

     if kwargs["tweet"]:
       #tweet = api.get_status(1242510872880259073)
       try:
          tweet = api.get_status(kwargs["tweet"][0], tweet_mode="extended")

          l.info ('## Information of tweet_id: ' + kwargs["tweet"][0])
          l.info ('################     tweet    ###################')
          l.info(tweet)
          l.info ('###################################')

       except:
           l.info("Tweet_id not found {}".format(kwargs["tweet"][0]))   
       sys.exit()

#Procesamiento normal, crea listener para escuchar en twitter y guardar en MISP
#Solo conecto a MISP con el parámetro -F
# Conexión con MISP
     l.info ("## Estableciendo Conexion a MISP ##")
     # The URL of the MISP instance to connect to
     misp_url = MISP_URL
         
     # Can be found in the MISP web interface under 
     # http://+MISP_URL+/users/view/me -> Authkey
     misp_key = MISP_TOKEN_ACCESS
     
     # Should PyMISP verify the MISP certificate
     misp_verifycert = False
     #Deshabilitar warning por no verificar certificado SSL
     urllib3.disable_warnings()
     
     try: 
        misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
        l.info ("## Conexion MISP establecida ##")
     except:
        l.info ('## Error en la conexion a MISP ##')
        raise MyException ('## Error en la conexion a MISP ##') from None
        sys.exit()

     l.info ('## Conexion a MISP establecida ##')
     
     if kwargs["list"]:
        cuentas = ''
        for cuenta in kwargs["list"]:
           l.info ('### ' + cuenta + ' ###')
           try:
              l.info (api.get_user(cuenta).id)
              cuentas = cuentas + str(api.get_user(cuenta).id) + ','
           except:
              l.info("User not found {}".format(cuenta))
              continue
    # Quita la coma final   
        cuentas = cuentas[:-1]
        l.info ('### Lista de Twitter ID users ###')
        l.info (cuentas)    

     
     if kwargs["file"]:
        cuentas = '' 
        l.info ('### ' + kwargs["file"][0] + ' ###')
        f = open(kwargs["file"][0], "r")
        for cuenta in f:
           # Elimina salto de línea final
           cuenta_sinsalto = cuenta[:-1]
           l.info ('### ' + cuenta_sinsalto + ' ###')
           try:
              l.info (api.get_user(cuenta_sinsalto).id)
              cuentas = cuentas + str(api.get_user(cuenta_sinsalto).id) + ','
           except:
              l.info("User not found {}".format(cuenta_sinsalto))
              continue
    # Quita la coma final              
        cuentas = cuentas[:-1]
        l.info ('### Lista de Twitter ID users ###')
        l.info (cuentas)   
     if len(cuentas)==0:
        l.info ('### No existe ninguna cuenta de las proporcionadas ###')   
        sys.exit()
      
#stream.py -F cuentas.txt
#stream.py -L xfjimcas cyb3rops VK_Intel Manu_De_Lucia Kyeehmke Securityartwork

     while True:
       try:
           stream.filter(follow=[cuentas])
       except ProtocolError as e:
           l.info(e)
           continue



