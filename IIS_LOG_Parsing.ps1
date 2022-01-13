# Permet de parser des logs IIS rapidement à la recherche d'un pattern
# Executer le script depuis le dossier suivant pour parser les logs IIS (SAUF SI LE CHEMIN EST DIFFERENT) : 
# "C:\inetpub\logs\LogFiles\W3SVC1"

#HAFNIUM Patterns
#Quick check : '((POST.*\/aspnet_client\/)|(system_web\/[A-Za-z0-9]{8}\.aspx|\/ecp\/y\.js)).*2[0-9]{2}\s[0-9]+'
#Classic check : '(python-requests|ExchangeServicesClient\/0\.0\.0\.0|system_web|172\.104\.251\.234|23\.101\.135\.86|34\.78\.227\.165|35\.187\.190\.226|82\.221\.139\.240|86\.105\.18\.116|165\.232\.154\.116|157\.230\.221\.198|104\.248\.49\.97|ecp\/y\.js|supp0rt|\/(shell|one|xx|[A-Za-z]{1})\.aspx|aspnet_client|system_web|RedirSuiteServerProxy)'


$RGX_pattern = "Transfer-Encoding: chunked"

Select-String -Pattern $RGX_pattern *.log | export-csv -Append "IIS_Log_parsing.csv"
