# mattermost

Tool I wrote for a class to parse through some of the MySQL relevant data. There is still tons to do. This is just the beginning.

Use the mysqldump tool to extract the database.

Usage: mysqldump -u root -p <database> > backup.sql

Usage: python mmdb.py -i backup.sql -o output.txt -l logging.txt
