# AI Eye - Model Security Scanner 🛡️

A security analysis tool for HuggingFace AI models that scans for malicious code, unsafe serialization, and compliance issues.

## Features
- 🔍 Real-time model scanning via HuggingFace API
- ⚠️ Detects unsafe pickle files & executables
- 📊 Risk scoring algorithm
- 🌓 Dark/Light theme
- 📱 Responsive design

## Tech Stack
- React 18 + TypeScript
- Vite
- Tailwind CSS
- Lucide React Icons

## Security Checks Performed
- Unsafe serialization formats (pickle, joblib, dill)
- Executable files (.exe, .bin, .dll)
- Source code files (.py, .sh, .js)
- License compliance
- Dataset linkage analysis

## Future Enhancements
- [ ] Backend API rate limiting
- [ ] Model comparison feature
- [ ] PDF report export
- [ ] Historical scan database
- [ ] CVE database integration
- [ ] Webhook notifications

## Contributing
Built for AI security research and red teaming.
