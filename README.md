# CampusGigs - Student Gig Marketplace 🎓
CampusGigs is a **student-run job posting platform** where students can **post, accept, and complete short-term gigs** within their university. It fosters a **free-market system** for on-campus jobs like food delivery, academic help, and creative work.

## Tech - Stack 💻 📀 
 - MongoDB hosted via MongoDB Atlas
 - Communications between the database server and the front end is done via a flask app, using pymongo python library
 - FuzzyBuzzy search used for search used
 - HTML, CSS and JS along with bootstrap used for front end. 

## 📸 Screenshots


## 🛠 Installation & Setup
- First clone the repo onto your local machine using git clone
## Make sure you have the latest version of MongoDB, and run these commands for mac-os:
   - brew tap mongodb/brew
   - brew install mongodb-community@7.0
   - brew services start mongodb-community@7.0
## Run these commands for Windows via chocolatey: 
   - choco install mongodb-community --version=7.0
   - net start mongodb
   - mongod --dbpath "C:\data\db"
   - sc config mongodb start=auto
## Via Winget: 
   - winget install MongoDB.Server --version 7.0
   - net start MongoDB
  ## Then run the following commands:
  - pip3 install -r requirements.txt
  - python3 -m flask run 
  

