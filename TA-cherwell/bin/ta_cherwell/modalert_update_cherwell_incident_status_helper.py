import splunk.search as splunk_search
import splunk.rest
import json
from cherwellutility import get_access_token, post_api_call_response, get_api_call_response
from datetime import datetime
from datetime import timedelta
import logging
# encoding = utf-8

def process_event(helper, *args, **kwargs):

    helper.log_info("[Update Status] Alert action update_cherwell_incident_status started.")

    # Getting configured items from the custom alert page.
    account_name = helper.get_param("account")
    events = helper.get_events()
    event_id = None # ITSI notable event id.
    itsi_group_id = None   # ITSI group id.
    ticket_ids = [] # List of ITSI attached tickets to particular group.
    itsi_group_status = None # ITSI group status.
    incident_status_from_cherwell = {} # dict of status of ant particular ticket ids.
    update_status_required = [] # list of dict with ids and latest status of the tickets which we will update on the cherwell server.
    # ITSI Status Details: 0-Unassigned, 1-New, 2-InProgress, 3-Pending, 4-Resolved, 5-Closed
    status_mapping = {"0": "New", "1" : "New", "2" : "In Progress", "3": "Pending", "4": "Resolved", "5": "Closed"}

    user_account = helper.get_account_credential(account_name)
    url_scheme = user_account.get('url_scheme')
    ipaddress = user_account.get('ipaddress')
    username = user_account.get('username')
    password = user_account.get('password')
    clientid = user_account.get('clientid')
    ssl_verify = user_account.get('ssl_verify')
    proxy_uri = helper._get_proxy_uri()
    app_name = helper.app
    
    # First eventID from the group to get the itsi group id.
    for event in events:
        event_id = event.get('event_id', None)
        break
    helper.log_debug("[Update Status] Got event id from the ITSI alert: {}".format(event_id))

    # Take itsi group id from the index=itsi_grouped_alerts for particular eventID.
    if event_id:
        searchquery_oneshot = "| search index=itsi_grouped_alerts " + str(event_id) + "| head 1 |table itsi_group_id"
        session_key = helper.session_key
        results = splunk_search.searchAll(searchquery_oneshot, sessionKey=session_key)
        for data in results:
           itsi_group_id = data["itsi_group_id"] if data["itsi_group_id"] is not None else None
        helper.log_debug("[Update Status] Got the itsi_group_id {}".format(itsi_group_id))
    # Get call to ticketing rest endpoint to find the attached ticket for particular notable event group.
    try:
        ticket_info_response = splunk.rest.simpleRequest(
            "/servicesNS/nobody/SA-ITOA/event_management_interface/ticketing/%s" % str(itsi_group_id), sessionKey=helper.session_key, method='GET',
            getargs={"output_mode": "json"}, raiseAllErrors=True)

        if int(ticket_info_response[0]["status"]) != 200:
            raise Exception("Not able to get info of the attached ticket for the itsi group id:{}".format(itsi_group_id))
    except Exception as e:
        helper.message('[Update Status]' + str(e), status="failure", level=logging.ERROR)
    
    if ticket_info_response:
        ticket_info_response = json.loads(ticket_info_response[1])
        for data in ticket_info_response:
            for ticket in data.get("tickets"):
                ticket_ids.append(ticket.get("ticket_id"))
            helper.log_info("[Update Status] Got ticket ids:{}".format(",".join(ticket_ids)))
    else:
        helper.log_info("[Update Status] No tickets attached with the ITSI group.")
        return

    # From the correlation search you can assign the default status to notable events. In ITSI if you change the status from notable review page, it will
    # store the in  itsi_notable_event_group_lookup. We will use the rest API call notable_event_group to get the data. So we need to check the status in kvstore first and then index=itsi_grouped_alerts.
    try:
        group_status_response = splunk.rest.simpleRequest(
            '/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group?filter={"_key":"%s"}' % str(itsi_group_id), sessionKey=helper.session_key, method='GET',
            raiseAllErrors=True)
        if int(group_status_response[0]["status"]) != 200:
            helper.log_error("[Update Status] Not able to get status info for the itsi group id:{}".format(itsi_group_id))
            raise Exception
    except Exception as e:
        helper.log_error("[Update Status] Got Exception: {}".format(e))
    if  group_status_response:
        group_status_response = json.loads(group_status_response[1])
        for data in group_status_response:
            itsi_group_status = data.get("status")
    
    # From the correlation search you can assign the default status to notable events. In ITSI if you change the status from notable review page, it will
    # store the in  itsi_notable_event_group_lookup. So we need to check the status in kvstore first and then index=itsi_grouped_alerts.
    # search_status_oneshot = "| inputlookup itsi_notable_event_group_lookup | search _key=\"" + str(itsi_group_id) + "\" | head 1 | table status"
    # search_status_results = splunk_search.searchAll(search_status_oneshot, sessionKey=session_key)
    # if search_status_results:
    #     for data in search_status_results:
    #         itsi_group_status = data["status"]
    if not itsi_group_status:
        search_itsi_group_status_oneshot = "| search index=itsi_grouped_alerts itsi_group_id=\"" + str(itsi_group_id) + "\" | head 1 | table itsi_group_status"
        search_itsi_group_status_results = splunk_search.searchAll(search_itsi_group_status_oneshot, sessionKey=session_key)
        if search_itsi_group_status_results:
            for data in search_itsi_group_status_results:
                itsi_group_status = data["itsi_group_status"]
    helper.log_info("[Update Status] Got the itsi group status {}".format(itsi_group_status))


    # Get Access Token from Cherwell
    try:
        access_token = get_access_token(url_scheme=url_scheme, ipaddress=ipaddress, username=username,
                        password=password, clientid=clientid, ssl_verify=ssl_verify, proxy_uri= proxy_uri)
    except Exception as e:
        helper.message('[Update Status] Not able to get access token from cherwell account, Error: ' + str(e), status="failure", level=logging.ERROR)

    # getbusinessobjectsummary to get the business Object ID from Cherwell Splunk Incident Business Object
    try:
        summary_details = get_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="getbusinessobjectsummary/busobname/Incident",
                        auth_token=access_token, data=None, clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
        business_object = summary_details[0].get('busObId')
    except Exception as e:
        helper.message('[Update Status] Not able to get business object from cherwell account, Error: ' + str(e), status="failure", level=logging.ERROR)

    # getbusinessobjectschema to get fieldIds from Cherwell Splunk Incident Business Object
    try:
        schema_details = get_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="getbusinessobjectschema/busobid/" + str(business_object),
                        auth_token=access_token, data=None, clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
        field_ids = {}
        for data_obj in schema_details.get('fieldDefinitions'):
            if data_obj.get('name') in ['Status', 'IncidentID', 'ReviewByDeadline', 'PendingReason']:
                field_ids.update({data_obj.get('name'): data_obj.get('fieldId')})
    except Exception as e:
        helper.message('[Update Status] Not able to get fieldIds from cherwell account, Error: ' + str(e), status="failure", level=logging.ERROR)
    for ids in ticket_ids:
        incident_filter = {
               "busObId":str(business_object),
               "fields": [str(field_ids.get('Status'))],
               "filters": [{"fieldId": str(field_ids.get('IncidentID')), "operator": "=", "value": str(ids)}]
        }
        # getsearchresults to get the status of the IncidentID
        try:
            status_response = post_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="getsearchresults",
                            auth_token=access_token, data=json.dumps(incident_filter), clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
            for status_values in status_response.get('businessObjects'):
                for status_value in status_values.get('fields'):
                    incident_status_from_cherwell.update({ids : status_value.get('value')})
            helper.log_info("[Update Status] Got the status from the cherwell Incident. Details: {}".format(incident_status_from_cherwell))
            
        except Exception as e:
            helper.message('[Update Status] Not able to get status from cherwell account, Error: ' + str(e), status="failure", level=logging.ERROR)

    for ids in ticket_ids:
        helper.log_debug("[Update Status] Checking for updatation for IncidentID: {}, Cherwell Status: {}, ITSI Status: {}".format(ids, incident_status_from_cherwell.get(ids), itsi_group_status))
        if incident_status_from_cherwell.get(ids) != status_mapping.get(str(itsi_group_status)):
           update_status_required.append({"id": ids, "status": status_mapping.get(str(itsi_group_status))})
    
    helper.log_info("[Update Status] Details of the updation required Incident: {}".format(update_status_required))

    # update the status on the cherwell incident.
    if update_status_required:
        for update_incident in update_status_required:
                data = {
                 "busObId": str(business_object),
                 "fields": [
                    {
                      "name": "Status",
                      "value": str(update_incident.get('status')),
                      "fieldId": str(field_ids.get("Status")),
                      "dirty": "true"
                    }
                ],
                "persist": "true",
                "busObPublicId": str(update_incident.get("id"))
                }
                # PendingReason and ReviewByDeadline fields are required for Pending status.
                if str(update_incident.get('status')) == "Pending":
                    deadline= datetime.now() + timedelta(days=1)
                    data.get("fields").append({
                                             "name": "PendingReason",
                                             "value": "Not Available",
                                             "fieldId": str(field_ids.get("PendingReason")),
                                             "dirty": "true"
                                            })
                    data.get("fields").append({
                                             "name": "ReviewByDeadline",
                                             "value": str(deadline.strftime("%m/%d/%Y")),
                                             "fieldId": str(field_ids.get("ReviewByDeadline")),
                                             "dirty": "true"
                                            })
                try:
                    response_data = post_api_call_response(url_scheme=url_scheme, ipaddress=ipaddress, api_endpoint="savebusinessobject",
                                auth_token=access_token, data=json.dumps(data), clientid=clientid, ssl_verify=ssl_verify, proxy_uri=proxy_uri)
                    helper.log_info("[Update Status] Incident updated successfully on cherwell server: %s, Incident ID: %s, Status: %s" %(user_account.get('ipaddress'), response_data.get('busObPublicId'), update_incident.get('status')))
                except Exception as e:
                    helper.message("[Update Status] Unable to update incident Incident ID: %s, Status: %s, Error: %s" % (update_incident.get("id"), update_incident.get('status'), e), status="failure", level=logging.ERROR)
    else:
    	helper.log_info("[Update Status] Attached Incidents are already updated. No action required.")
    return 0