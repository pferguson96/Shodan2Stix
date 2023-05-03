#!/usr/bin/env python

import argparse
import os
import json
from datetime import datetime

import shodan
from stix2 import Indicator, Infrastructure, Malware, Bundle, Tool, Relationship

def list_searches():
    """This function lists the searches and their metadata currently stored in the searches/searches.json file"""
    current_dir = os.getcwd()
    searches_file = '{}/searches/searches.json'.format(current_dir)
    try:
        search_description = ''
        with open(searches_file, 'r') as data:
            searches = json.load(data)

            for search in searches["searches"]:
                try:
                    search_description += f"Search: {search['search']}\n"
                except KeyError:
                    pass

                try:
                    search_description += f"Confidence: {search['confidence']}\n"
                except KeyError:
                    pass

                try:
                    search_description += f"Tool: {search['tool']}\n"
                except KeyError:
                    pass

                try:
                    search_description += f"Malware: {search['malware']}\n"
                except KeyError:
                    pass

                try:
                    search_description += f"Description: {search['description']}\n"
                except KeyError:
                    pass
                
                try:
                    search_description += f"Tags: {', '.join(search['tags'])}\n"
                except KeyError:
                    pass

                try:
                    search_description += f"ID: {str(search['id'])}\n\n"
                except KeyError:
                    pass
        print(search_description)
        return True
    except FileNotFoundError:
        print('The searches file does not exist, use the -a argument to create a new search which will automatically create a searches file for you')
        return False

def add_search():
    """
    This function adds a search to the search.json file
    If the file does not exist it will create a search.json file in the searches folder 
    """
    current_dir = os.getcwd()
    searches_file = f"{current_dir}/searches/searches.json"
    search_structure = {
        "searches": []
    }

    new_search = {}

    if not os.path.exists(searches_file): # Condition taken if searches.json file does not exist in searches folder
        with open(searches_file, 'w') as f:
            shodan_search = input("shodan search: ")
            shodan_search = shodan_search.replace('"', '\"') # Formats the inputted search string so its stored correctly

            continue_while_loop = True
            while continue_while_loop:
                confidence = input("Confidence of search (high / medium / low): ")
                if confidence in ["high", "medium", "low"]:
                    break
                else:
                    print("Please input 'high', 'medium' or 'low'.")

            tool = input("The tool associated to the search, leave blank if unapplicable: ")
            malware = input("The malware associated to the search, leave blank if unapplicable: ")
            description = input('Description of the search: ')
            tags = input('Metadata tags for the search - Add a whitespace between each tag: ')
            tag_list = tags.split()

            new_search["search"] = shodan_search
            new_search["confidence"] = confidence
            new_search["tool"] = tool
            new_search["malware"] = malware
            new_search["description"] = description
            new_search["tags"] = tag_list
            new_search["id"] = 1

            search_structure["searches"].append(new_search)

            json.dump(search_structure, f)
            
            return "searches.json file created - search added with id:1"

    if os.path.exists(searches_file):
        try:
            with open(searches_file, 'r') as data:
                searches = json.load(data)

                shodan_search = input("shodan search: ")
                shodan_search = shodan_search.replace('"', '\"')
            
                continue_while_loop = True
                while continue_while_loop:
                    confidence = input("Confidence of search (high / medium / low): ")
                    if confidence in ["high", "medium", "low"]:
                        break
                    else:
                        print("Please input 'high', 'medium' or 'low'.")

                tool = input("The tool associated to the search, leave blank if unapplicable: ")
                malware = input("The malware associated to the search, leave blank if unapplicable: ")
                description = input('Description of the search: ')
                tags = input('Metadata tags for the search - Add a whitespace between each tag: ')
                tag_list = tags.split()

                id_num_list = []
                for search in searches["searches"]:
                    id_num_list.append(search["id"])
                highest_id = max(id_num_list)
                id = highest_id + 1

                new_search["search"] = shodan_search
                new_search["confidence"] = confidence
                new_search["tool"] = tool
                new_search["malware"] = malware
                new_search["description"] = description
                new_search["tags"] = tag_list
                new_search["id"] = id

                searches["searches"].append(new_search)

                with open(searches_file, 'w') as f:
                    json.dump(searches, f)

                print(f"search added with id:{id}")

        except json.decoder.JSONDecodeError:
            
            print("There was an error decoding the JSON file, press 1 to delete automatically or 0 to manually fix it.")

            continue_while_loop = True
            while continue_while_loop:
                user_input = input("Input 1 or 0:")
                if user_input in ["1", "0"]:
                    if user_input == "1":
                        os.remove(searches_file)
                        print("searches.json removed.")
                    if user_input == "0":
                        print("searches.json not removed.")

                    break
                else:
                    print("Please input 1 or 0.")

        return True 

def get_id_info(id):
    """This function take a search ID as input and returns the related Shodan search, tags, malware & tool fields as a list of strings"""
    current_dir = os.getcwd()
    searches_file = '{}/searches/searches.json'.format(current_dir)

    if not os.path.exists(searches_file):
        return 'The searches file does not exist, use the -a argument to create a new search which will automatically create a searches file for you'

    if os.path.exists(searches_file):
        with open(searches_file, 'r') as data:
            searches = json.load(data)
            for search in searches["searches"]:
                if search["id"] is id:
                    shodan_search = search["search"]
                    search_tags = search["tags"]
                    confidence = search["confidence"]
                    malware = search["malware"]
                    tool = search["tool"]
                else:
                    pass

        return shodan_search.strip(), search_tags, malware.strip(), tool.strip()

def search_by_id(id, api_key):
    """
    This function searches shodan using an inputted from the searches.json file and creates a STIX2.1 bundle from the results"""
    api = shodan.Shodan(api_key)
    id_info = get_id_info(id)
    query=id_info[0]
    query_tags = id_info[1]
    query_malware = id_info[2]
    query_tool  = id_info[3]

    try:
        ip_list = []
        response = api.search_cursor(query=query)
        for ip in response:
            ip_list.append(ip)
    except shodan.APIError as e:
        return "Error: " + e

    indicator_list = []
    relationship_list = []

    if query_malware:
        infrastructure = Infrastructure(
            name=f"{query_malware} Infrastructure",
            labels=query_tags
        )
        malware = Malware(
            name=f"query_malware",
            is_family=False,
            labels=query_tags
        )
        mal_infra_relationship = Relationship(
            relationship_type="uses",
            source_ref=malware.id,
            target_ref=infrastructure.id
        )
        relationship_list.append(mal_infra_relationship)

    elif query_tool:
        infrastructure = Infrastructure(
            name=f"{query_tool} Infrastructure",
            labels=query_tags
        )
        tool = Tool(
            name=query_tool,
            labels=query_tags
        )
        tool_infra_relationship = Relationship(
            relationship_type="uses",
            source_ref=tool.id,
            target_ref=infrastructure.id
        )
        relationship_list.append(tool_infra_relationship)

    else:
        print("Please make sure your search has the tool or malware field filled out, the script is unable to proceed otherwise")
        quit()

    for ip in ip_list:
            try:
                indicator = Indicator(
                    name=ip["ip_str"],
                    pattern=f"[ipv4-addr:value = '{ip['ip_str']}']",
                    pattern_type="stix",
                    labels=query_tags,
                )

                ind_infra_relationship = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=infrastructure.id
                )

                indicator_list.append(indicator)
                relationship_list.append(ind_infra_relationship)
            except KeyError:
                continue
    
    if query_malware:
        bundle = Bundle(infrastructure, malware, indicator_list, relationship_list)
    if query_tool:
        bundle = Bundle(infrastructure, tool, indicator_list, relationship_list)

    currentDateAndTime = datetime.now().strftime("%Y:%m:%d_%H:%M:%S")
    with open(f"bundles/{currentDateAndTime}.json", "w", encoding="utf-8") as f:
        stix_bundle = bundle.serialize(pretty=True, encoding="utf-8", ensure_ascii=False)
        f.write(stix_bundle)

    return "Bundle was successfully created"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'The Shodan2Stix script allows a user to search the Shodan API and create a STIX2.1 bundle from the results. Searches can be saved allowing a user to build out a library of searches that they can use to track specific infrastructure.',
        epilog='Authored by Peter Ferguson'
    )
    parser.add_argument(
        '-q',
        '--searches',
        action='store_true',
        help='The -q argument lists all of the available searches currently stored in the searches.json file',
    )
    parser.add_argument(
        '-a',
        '--add',
        action='store_true',
        help='The -a argument takes a shodan search as a string and adds the search to the searches.json file'
    )
    parser.add_argument(
        '-s',
        '--search',
        help='The -s argument takes a shodan search as a string and runs it against Shodans API, creating a STIX2.1 bundle from returned data.'
    )
    parser.add_argument(
        '-id',
        '--identity',
        type=int,
        help='The -id argument takes an integer and runs the search from searches.json with the id number matching the input'
    )
    parser.add_argument(
        '-k',
        '--key',
        help='The -k argument takes a Shodan API key as a value'
    )

    args = parser.parse_args()

    if args.searches:
        print(list_searches())
    if args.add:
        print(add_search())
    if args.identity and args.key:
        print(search_by_id(args.identity, args.key.strip()))