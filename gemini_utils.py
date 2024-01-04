import os
from dotenv import load_dotenv
import pathlib
import textwrap
import markdown

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

BASE_PROMPT_ACTION = """
Analyze the following static analysis report of an app and suggest the possible action that the client user should take on his phone based on the report findings.
Make sure that you suggest with the best suitable action.
It can be possible that the app's permissions in the json is being used fully and accordingly to the playstore description of the api.
Vice Versa, it can be possible that the app is taking a lot of permissions but not using them.
So make sure that you provide the best suitable action for the user.
Provide no headings.
Make sure that the action is briefly explained in strictly under 150 characters as a paragraph and not separate points.
Make sure that the action is best suited based upon the findings in the code, permissions, strings etc mentioned in the json attached.
Make sure that the action provided is feasible to perform by a normal non tech savy client user from his mobile phone.
Keep in mind that the user performing the action is not a tech savy client and is not able to edit the app code.
Keep the text limit strictly under 150 characters! And if possible under 100 characters.
You are not allowed to write more than 150 characters at any cost.
The report of the static analysis is attached below in json format.
"""

BASE_PROMPT_SUMMARY = """
Analyze the following static analysis report of an app and provide a brief summary in a non technical layman language for the client.
Provide no headings.
Focus majorly on vulnerability issues related to permissions, code_analysis, manifest_analysis, etc keys in the attached static analysis json.
Make sure that the summary is briefly explained in strictly under 150 characters as a paragraph and not separate points.
Utilise the properties like manifest_analysis, permissions, playstore summary, etc to create a summary of the whole json report of the apk's static analysis.
Make sure that the summary is understandable by a normal user who has no technical knowledge.
Only summary of the report is to be provided.
Make sure to do not mention any keys or technical permissions, technical terms which is there in the static analysis JSON report in the summary.
The summary is for the client to understand the report in a non technical language. So, do not write anything related to developer or technical terms.
Keep the text limit STRICTLY under 150 characters! And if possible under 100 characters.
You are not allowed to write more than 150 characters at any cost.
I will not use you if you do not follow the above instructions.
The report of the static analysis is attached below in json format.
"""
