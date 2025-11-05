python main.py --username sj --password 123
python main.py --username sj2 --password 12345

python main.py --username sj --password 123 --filepath file/NEWS.docx --behavior encrypt
python main.py --username sj --password 123 --filepath file/NEWS.docx.enc --behavior decrypt


python main.py --username sj2 --password 12345 --filepath file/NEWS.docx.enc --behavior decrypt
python main.py --username sj --password 123 --filepath file/NEWS.docx.enc --behavior share --memname sj2
python main.py --username sj2 --password 12345 --filepath file/NEWS.docx.enc --behavior decrypt
