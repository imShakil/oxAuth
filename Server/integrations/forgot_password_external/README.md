# Update External User Password with 2FA Token

## Description

This a 2FA token based password reset interception script. With this script external users can update their passwword locally in gluu and also in external LDAP server. 

## How It Works?

- Step 1: User enters e-mail and if e-mail exists, user receive a token via email
- Step 2: User enters token received by e-mail
- Step 3: User enters new password

## Installation

1. create a json file `/etc/certs/external_ldap_conf.json` with below informations:

```
{
	"ldaps_url": "ldaps://[Server IP]:[PORT]",
	"bind_dn": "BIND DN",
	"bind_password": "<encoded password>",
	"base_dn": "BASE DN",
	"primary_key": "uid"
}
```
- To encode password, please use this script: `/opt/gluu/bin/encode.py`

2. give file permission:
```
chown -R root:gluu /etc/certs/external_ldap_conf.json
chmod 660 /etc/certs/external_ldap_conf.json
```
3. Add custom script in `Person Authentication Script`
4. Set a custom attribute key as `EXTERNAL_LDAP` and put value as the json file path.
5. Enable this custom script


