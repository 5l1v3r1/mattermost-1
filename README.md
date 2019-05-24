# MySQL Mattermost Forensics

Tool I wrote for a class to parse through some of the MySQL relevant data. There is still tons to do. THis was just for the assignment to show POC :).

Use the mysqldump tool to extract the database.

Usage: mysqldump -u root -p <database> > backup.sql

Usage: python mm_dump.py -i backup.sql -o output.txt -l logging.txt
