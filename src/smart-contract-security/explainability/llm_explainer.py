from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

class LLMExplainer:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained('gpt2')
        self.model = AutoModelForCausalLM.from_pretrained('gpt2')
    
    def generate_explanation(self, prediction, features, code_snippet):
        input_text = f'Contract risk analysis prediction: {prediction:.2f}\nFeatures: {features}\nCode snippet: {code_snippet}\nExplain why this contract has this risk level in plain language:'
        
        inputs = self.tokenizer(input_text, return_tensors='pt')
        with torch.no_grad():
            output = self.model.generate(**inputs, max_new_tokens=150)
        return self.tokenizer.decode(output[0], skip_special_tokens=True)
    
    # Fixed string termination and added semicolons between statements

    pass

    # Example usage
    if __name__ == '__main__':
        explainer = LLMExplainer()
        print(explainer.generate_explanation(0.85, {'function_count': 12, 'security_flags': 1}, 'function riskyOperation { revert(); }'))
