#!/usr/bin/env python3

import argparse
import sqlite3
from Crypto.Cipher import AES
import sys
import pyperclip
import os
from pathlib import Path

def init():
  os.makedirs('/etc/savepass', exist_ok=True)

  conn = sqlite3.connect(os.path.abspath('/etc/savepass/store.db'))
  cursor = conn.cursor()

  # Execute a SQL query to create a table if it doesn't exist
  create_table_query = '''
  CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      encrypted_password BLOB
  );
  '''

  cursor.execute(create_table_query)

  conn.commit()
  conn.close()

def get_key():
  with open(os.path.abspath('/etc/savepass/.key'), 'r') as f:
    key = f.read()
    return key.encode('utf-8')

def add(cursor):
  name = input('name: ')
  password = input('password: ')

  key = get_key()

  cipher = AES.new(key, AES.MODE_EAX)

  ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))

  encrypted_password = cipher.nonce + ciphertext + tag

  # Execute a SQL query to create a table if it doesn't exist
  insert_query = '''
  INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)
  '''
  cursor.execute(insert_query, (name, sqlite3.Binary(encrypted_password)))

  print(f'password with name {name} added successfully')

def list_operation(cursor):
  # Execute a SQL query to create a table if it doesn't exist
  select_query = '''
  SELECT name from passwords
  '''
  cursor.execute(select_query)

  rows = cursor.fetchall()

  for row in rows:
    print(row[0])

def delete(cursor):
  name = input('name: ')

  # Execute a SQL query to create a table if it doesn't exist
  select_query = '''
  SELECT name from passwords WHERE name=(?)
  '''
  cursor.execute(select_query, (name, ))

  rows = cursor.fetchall()

  if len(rows) == 0:
    print('name doesn\'t exist')
    sys.exit()

  delete_query = '''
  DELETE from passwords where name=(?)
  '''
  cursor.execute(delete_query, (name, ))

  print(f'password with name {name} deleted successfully')

def get(cursor):
  name = input('name: ')

  # Execute a SQL query to create a table if it doesn't exist
  select_query = '''
  SELECT name, encrypted_password from passwords where name=(?)
  '''
  cursor.execute(select_query, (name, ))

  rows = cursor.fetchall()
  if len(rows) == 0:
    print('name doesn\'t exist')
    sys.exit()
  
  encrypted_password = rows[0][1]
  nonce = encrypted_password[:16]
  ciphertext = encrypted_password[16:-16]
  tag = encrypted_password[-16:]

  key = get_key()
  
  cipher = AES.new(key, AES.MODE_EAX, nonce)
  plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()

  pyperclip.copy(plaintext)

  print(f'password with name {name} copied to clipboard')

def has_init():
  return Path(os.path.abspath('/etc/savepass/store.db')).exists() and Path(os.path.abspath('/etc/savepass/.key')).exists()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='savepass: save your passwords locally')
  parser.add_argument('operation', default='help', help='init|add|list|get|delete', nargs='?')

  args = parser.parse_args()

  operation = args.operation

  if operation == 'init': init()
  else:
    if operation != 'init' and not has_init():
      print('please init first')
      sys.exit()
      
    conn = sqlite3.connect(os.path.abspath('/etc/savepass/store.db'))
    cursor = conn.cursor()

    if operation == 'add': add(cursor)
    elif operation == 'list': list_operation(cursor)
    elif operation == 'delete': delete(cursor)
    elif operation == 'get': get(cursor)
    elif operation == 'help': parser.print_help()

    conn.commit()
    conn.close()
