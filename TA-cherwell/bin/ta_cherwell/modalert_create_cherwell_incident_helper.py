from cherwellutility import get_access_token, post_api_call_response, get_api_call_response
import json
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """ This method will create an incident on the selected business object on cherwell server.

    :param helper:
    :param args:
    :param kwargs:
    :return:
    """

    helper.log_info("Alert action create_cherwell_incident started.")

    # Getting configured items from the custom alert page.
    account_name = helper.get_param("account")
    description = helper.get_param("description")
    priority = helper.get_param("priority")
    short_description = helper.get_param("short_description")
    splunk_url = helper.get_param("splunk_url")
    index_name = helper.get_param("index_name")


    user_account = helper.get_account_credential(account_name)
    url_scheme = user_account.get('url_scheme')
    ipaddress = user_account.get('ipaddress')
    username = user_account.get('username')
    password = user_account.get('password')
    clientid = user_account.get('clientid')
    ssl_verify = user_account.get('ssl_verify')
    proxy_uri = helper._get_proxy_uri()
    app_name = helper.app

    events = helper.get_events()
    event_id = None
    for event in events:
        event_id = event.get('event_id', None)
        break
    # Get Access Token from Cherwell
    try:
        access_token = get_access_token(url_scheme=url_scheme, ipaddress=ipaddress, username=username,
                        password=password, clientid=clientid, ssl_verify=ssl_verify, proxy_uri= proxy_uri)
    except Exception as e:
        helper.log_error("Not able to get access token from cherwell account, Error : {}".format(e))
        raise

    # getbusinessobjectsummary to get the business Object ID from Cherwell Splunk Incident Business Object
    try:
        summary_details = get_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="getbusinessobjectsummary/busobname/SplunkIncidentStage",
                        auth_token=access_token, data=None, clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
        business_object = summary_details[0].get('busObId')
    except Exception as e:
        helper.log_error("Not able to get business object from cherwell account, Error : {}".format(e))
        raise

    # getbusinessobjectschema to get fieldIds from Cherwell Splunk Incident Business Object
    try:
        schema_details = get_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="getbusinessobjectschema/busobid/" + str(business_object),
                        auth_token=access_token, data=None, clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
        field_ids = {}
        for data_obj in schema_details.get('fieldDefinitions'):
            if data_obj.get('name') in ['Description', 'Priority', 'ShortDescription', 'SplunkURL', 'SplunkEventID']:
                field_ids.update({data_obj.get('name'): data_obj.get('fieldId')})
    except Exception as e:
        helper.log_error("Not able to get fieldIds from cherwell account, Error : {}".format(e))
        raise

    data = {
        "busObId": str(business_object),
        "fields": [
            {
                "name": "Description",
                "value": str(description),
                "fieldId": str(field_ids.get("Description")),
                "dirty": "true"
            },
            {
                "name": "Priority",
                "value": str(priority),
                "fieldId": str(field_ids.get("Priority")),
                "dirty": "true"
            },
            {
                "name": "ShortDescription",
                "value": str(short_description),
                "fieldId": str(field_ids.get("ShortDescription")),
                "dirty": "true"
            }
        ],
        "persist": "true"
    }
    
    if splunk_url:
        data.get("fields").append({
                "name": "SplunkURL",
                "value": str(splunk_url),
                "fieldId": str(field_ids.get("SplunkURL")),
                "dirty": "true"
            })

    if app_name.strip() == 'SA-ITOA':
        data.get("fields").append({
                "name": "SplunkEventID",
                "value": str(event_id),
                "fieldId": str(field_ids.get("SplunkEventID")),
                "dirty": "true"
            })
    try:
        response_data = post_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="savebusinessobject",
                        auth_token=access_token, data=json.dumps(data), clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
        helper.addevent(json.dumps(response_data), sourcetype="cherwell:alerts:response")
        helper.writeevents(index=str(index_name), source="cherwell:alerts:response", host=user_account.get('ipaddress'))
        helper.log_info("Incident created successfully on cherwell server: %s, Incident ID: %s" %(user_account.get('ipaddress'), response_data.get('busObPublicId')))
    except Exception as e:
        helper.log_error("Unable to create incident on business object id: %s Error: %s" % (business_object, e))

    return 0
