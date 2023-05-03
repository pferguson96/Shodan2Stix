# Shodan2Stix
Shodan2Stix is a command line tool to search Shodan's dataset and create a STIX2.1 bundle from the results.

The tool is currently a proof-of-concept (POC) and is not complete.

## Installation
To run the shodan2stix tool locally on your system, clone the shodan2stix repo.
```bash
git clone 
```

Move into the shodan2stix folder
```bash
cd shodan2stix
```

Install python3 virtual environment and run it
```bash
python3 -m venv env
source env/bin/activate
```

Install python packages
```bash
pip install -r requirements.txt
```

## Usage
The shodan2stix tool currently has 1 way of searching against Shodan:
- Creating and saving a search then searching by saved search ID

The searches used are the exact same syntax as the syntax accepted by the Shodan website.

See https://help.shodan.io/the-basics/search-query-fundamentals and https://www.shodan.io/search/filters for the official documentation around Shodan filters.

See https://github.com/jakejarvis/awesome-shodan-queries for some real world Shodan examples.

### Search by Saved Search ID
The anayst can create and save a search along with its metadata. The search is saved in the searches/searches.json file. They can then run the search by its ID value from the command line.

#### Creating a Search
To create a new search run the command:
```bash
python shodan2stix.py -a
```
This will return a selection of fields that you will need to fill in.
```
Shodan search: <The Shodan search you want to search for>

Confidence of search (high / medium / low): <Input one of the values in brackets>

What does the search detect (malware / tool): <Input one of the values in brackets>

Metadata tags for the search: <metadata tag - a space will create a new tag e.g. 'trojan malicious' will create the two tags 'trojan' 'malicious'>
```
Once all the fields have been created the search will be added to searches/searches.json with an ID.

#### Listing Saved searches
To list already saved searches along with their ID and metadata use the command:

```bash
python shodan2stix.py -q
```

#### Search by ID
To search Shodan by saved search ID and create a STIX2.1 bundle use the command:

```bash
python shodan2stix.py -id search_id -k shodan_api_key
```

## STIX2.1 Bundle
The STIX2.1 bundle created will be stored as a JSON file in the bundles folder. The name of the file is the current datetime. You can use tools like https://oasis-open.github.io/cti-stix-visualization/ to visualise the result of the script.