#testing cicd scan run

import os

import openai
from flask import Flask, redirect, render_template, request, url_for, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

openai.api_key = os.getenv("OPENAI_API_KEY")


@app.route("/chat", methods=["GET"])
def connect():
    return {"result":"connection successfull."}

@app.route("/chat/lib", methods=["POST"])
def lib():
    try:
        lib = request.json["libname"]
    except Exception as inputError:
        inputError = str(inputError) + " is missing."
        return inputError 

    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=generate_prompt(lib),
        temperature=0.7,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    response = {"result":response.choices[0].text}
    return response
  

@app.route("/chat/details", methods=["POST"])
def details():
    try:
        lib = request.json["libname"]
        func = request.json["funcname"]
    except Exception as inputError:
        inputError = str(inputError) + " is missing."
        return inputError 
    
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=generate_prompt2(lib,func),
        temperature=0.7,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    response = {"result":response.choices[0].text}
    return response
  

@app.route("/chat/code", methods=["POST"])
def code():
    
    try:
        lib = request.json["libname"]
        func = request.json["funcname"]
    except Exception as inputError:
        inputError = str(inputError) + " is missing."
        return inputError 

    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=generate_prompt3(lib,func),
        temperature=0.7,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    response = {"result":response.choices[0].text}
    return response


@app.route("/chat/vuln", methods=["POST"])
def vuln():
    
    try:
        vulnData = request.json["vulnname"]
        
    except Exception as inputError:
        inputError = str(inputError) + " is missing."
        return inputError 

    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=generate_prompt4(vulnData),
        temperature=0.7,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    response = {"result":response.choices[0].text}
    return response



def generate_prompt(lib):
    return """What is {} used for?""".format(
        lib
    )

def generate_prompt2(lib,func):
    return """What is the function {} in {} Library used for?""".format(
        func,lib
    )  
    
def generate_prompt3(lib,func):
    return """Generate a code example using {} in {} library""".format(
        func,lib
    )  

def generate_prompt4(vulnData):
    return """What is a {} vulnerability?""".format(
        vulnData
    )      
