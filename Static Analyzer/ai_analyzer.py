import logging
import os
from typing import Optional
import google.generativeai as genai
from openai import OpenAI

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """Unified Analyzer that uses Google Gemini or OpenAI to analyze assembly code"""
    
    def __init__(self, provider: str = "openai", api_key: Optional[str] = None, model: str = None):
        self.provider = provider
        self.api_key = api_key
        self.model_name = model
        self.client = None
        self.model = None

        if self.provider == "google":
            # Default Google key if not provided (from previous file)
            if not self.api_key:
                self.api_key = ''
            
            if not self.model_name:
                self.model_name = "gemini-2.5-pro"
                
            if not self.api_key:
                logger.warning("GOOGLE_API_KEY not found. AI analysis will be disabled.")
            else:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(self.model_name)
                
        elif self.provider == "openai":
            # Default OpenAI key if not provided (from previous file)
            if not self.api_key:
                self.api_key = ''
            
            if not self.model_name:
                self.model_name = "gpt-5.1"
                
            if not self.api_key:
                logger.warning("OPENAI_API_KEY not found. AI analysis will be disabled.")
            else:
                self.client = OpenAI(api_key=self.api_key)

    def recover_c_code(self, assembly_context: str) -> str:
        """
        Recover C code from assembly context.
        """
        if self.provider == "google" and not self.model:
            return "// AI Analysis disabled (no API key)"
        if self.provider == "openai" and not self.client:
            return "// AI Analysis disabled (no API key)"

        print(f"Recovering C code from assembly using {self.provider}...")

        prompt = f"""
Task: Reconstruct C code from the provided assembly code.

Context (Full Assembly Code):
{assembly_context}

Instructions:
1. Analyze the assembly code to understand the program logic.
2. Reconstruct the corresponding C code.
3. Include all functions found in the assembly. Do not change the function names.
4. Output ONLY the C code. Do not include explanations or markdown formatting.
"""

        try:
            if self.provider == "google":
                response = self.model.generate_content(prompt)
                return response.text
            elif self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a reverse engineering expert."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.0
                )
                return response.choices[0].message.content

        except Exception as e:
            logger.error(f"{self.provider} C recovery failed: {e}")
            return f"// C recovery failed: {str(e)}"

    def analyze_paths_bulk(self, paths_list: list, c_context: str) -> str:
        """
        Analyze multiple paths in bulk using recovered C code.
        """
        if self.provider == "google" and not self.model:
            return "[]"
        if self.provider == "openai" and not self.client:
            return "[]"

        print(f"Analyzing {len(paths_list)} paths in bulk using recovered C code ({self.provider})...")

        paths_text = "\n".join([f"ID {p['id']}: {p['path']} (Sink: {p.get('sink', 'Unknown')})" for p in paths_list])

        prompt = f"""
Analyze the following paths based on the provided recovered C code.

Context (Recovered C Code):
{c_context}

Paths to Analyze:
{paths_text}

Task:
For EACH path, perform the following:
1. **TRACE EXECUTION**: Trace the path in the C code.
2. **CHECK INPUT HANDLING**: Check for buffer size checks vs input limits.
3. **SECURITY ANALYSIS**: Focus on the specified 'Sink' function for this path. Verify if *that specific function call* is vulnerable (e.g., buffer overflow). Do not report vulnerabilities in other functions unless they directly affect the specified sink.
4. **VERDICT**: Determine if it is a True Positive or False Positive.

Knowledge Base (Ground Truth Patterns):
SAFE: strncpy(dest, src, n) where n <= sizeof(dest).
VULNERABLE: strcpy(dest, src) without prior length check.
VULNERABLE: fgets(buf, n, stdin) where n > sizeof(buf).
VULNERABLE: gets(buf).

Response Format:
You MUST return a JSON array of objects. Each object must have:
- "id": The path ID (integer).
- "verdict": "True Positive" or "False Positive".
- "reasoning": A concise explanation (max 2 sentences).

Example Output:
[
  {{ "id": 0, "verdict": "True Positive", "reasoning": "fgets reads 200 bytes into 100 byte buffer." }},
  {{ "id": 1, "verdict": "False Positive", "reasoning": "strncpy limit 50 matches buffer size 50." }}
]

Do not include markdown formatting (like ```json). Just the raw JSON array.
"""

        try:
            if self.provider == "google":
                response = self.model.generate_content(prompt)
                return response.text
            elif self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a vulnerability analysis expert. Output valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1
                )
                return response.choices[0].message.content

        except Exception as e:
            logger.error(f"{self.provider} bulk analysis failed: {e}")
            return "[]"

