#!/bin/bash

# Replace YOUR_USERNAME with your GitHub username
# Replace REPO_NAME with your repository name

echo "Enter your GitHub username:"
read USERNAME

echo "Enter your repository name (e.g., log4shell-security-lab):"
read REPO_NAME

# Add remote origin
git remote add origin https://github.com/$USERNAME/$REPO_NAME.git

# Push to main branch
git branch -M main
git push -u origin main

echo "Repository pushed successfully!"
echo "View at: https://github.com/$USERNAME/$REPO_NAME"