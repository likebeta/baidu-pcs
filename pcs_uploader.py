#!/usr/bin/python

#Author:likebeta
#Data: 2014-03-28
#Email: ixxoo.me@gmail.com

import sys
import os
import argparse
import json
import time
import oauth2
import urllib
import urllib2
import httplib
import base64
import hashlib
import mimetypes
import zlib
from poster.encode import multipart_encode
from poster.streaminghttp import StreamingHTTPHandler, StreamingHTTPRedirectHandler, StreamingHTTPSHandler

class BaiduPcs:
	def __init__(self,args):
		self.args = args
		self.__read_tokens()

	def run(self):
		if self.args.command == 'auth':
			self.__auth()
		elif self.args.command == 'quota':
			self.__quota()
		elif self.args.command == 'download':
			self.__download()
		elif self.args.command == 'list':
			self.__list()
		elif self.args.command == 'upload':
			self.__upload()
		elif self.args.command == 'rapidupload':
			self.__rapidupload()

	def __read_tokens(self):
		with open('pcs_token.json') as f:
			d = f.read()
			j = json.loads(d)
			for k,v in j.items():
				setattr(self,k,v)

		return True

	def __write_tokens(self):
		s = {}
		s['client_id'] = self.client_id
		s['client_secret'] = self.client_secret
		s['access_token'] = self.access_token
		s['refresh_token'] = self.refresh_token
		s['session_secret'] = self.session_secret
		s['session_key'] = self.session_key
		s['expires_in'] = int(time.time()) + self.expires_in
		s['scope'] = self.scope

		d = json.dumps(s)
		with open('pcs_token.json','w') as f:
			f.write(d)

		return True

	def __refresh_token(self):
		baseurl = 'https://openapi.baidu.com/oauth/2.0/token'
		params = {'grant_type':'refresh_token','refresh_token':self.refresh_token,'client_id':self.client_id,'client_secret':self.client_secret}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		data = self.__get(url)
		j = json.loads(data)
		if 'error' in j:
			print 'error:',j['error']
			print 'error_description:',j['error_description']
			return False

		for k,v in j.items():
			setattr(self,k,v)

		return self.__write_tokens() 

	def __check_tokens(self):
		if not getattr(self,'access_token'):
			print 'Please Auth first'
			return False

		if self.expires_in <= int(time.time()) + 60*60*24:
			return self.__refresh_token()
			
		return True

	def __get(self, url):
		request = urllib2.Request(url)
		response = urllib2.urlopen(request)
		return response.read()

	def __post(self, url, data="", headers=""):
		request = urllib2.Request(url, data, headers)
		response = urllib2.urlopen(request)
		return response.read()

	def __auth(self):
		baseurl = 'https://openapi.baidu.com/oauth/2.0/device/code'
		params = {'client_id':self.client_id,'response_type':'device_code','scope':'basic,netdisk'}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		data = self.__get(url)
		j = json.loads(data)
		if 'error' in j:
			print 'error:',j['error']
			print 'error_description:',j['error_description']
			return False

		print 'please open "%s",if asked for code, input "%s", then press enter' % (j['verification_url'],j['user_code'])
		raw_input('')
		baseurl = 'https://openapi.baidu.com/oauth/2.0/token'
		params = {'grant_type':'device_token','code':j['device_code'],'client_id':self.client_id,'client_secret':self.client_secret}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		data = self.__get(url)
		j = json.loads(data)
		if 'error' in j:
			print 'error:',j['error']
			print 'error_description:',j['error_description']
			return False

		for k,v in j.items():
			setattr(self,k,v)

		if self.__write_tokens():
			print 'Auth success'
			return True
		else:
			print 'Auth failed'
			return False

	def __quota(self):
		baseurl = 'https://pcs.baidu.com/rest/2.0/pcs/quota'
		params = {'method':'info','access_token':self.access_token}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		data = self.__get(url)
		j = json.loads(data)
		if 'error_code' in j:
			print 'error_code:',j['error_code']
			print 'error_msg:',j['error_msg']
			return False

		print 'Total:',to_human_see(j['quota'])
		print 'Used: ',to_human_see(j['used'])
		return True

	def __list(self):
		baseurl = 'https://pcs.baidu.com/rest/2.0/pcs/file'
		params = {'method':'list','access_token':self.access_token,'path':self.args.dir_path}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		data = self.__get(url)
		j = json.loads(data)
		if 'error_code' in j:
			print 'error_code:',j['error_code']
			print 'error_msg:',j['error_msg']
			return False

		for item in j['list']:
			if item['isdir'] == 1:
				print('%10s    %s'%('---',item['path']))
			elif item['isdir'] == 0:
				print('%10s    %s'%(to_human_see(item['size']),item['path']))

		return True

	def __download(self):
		baseurl = 'https://d.pcs.baidu.com/rest/2.0/pcs/file'
		params = {'method':'download','access_token':self.access_token,'path':self.args.remote_path}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		if self.args.get:
			print url
			return True

		data = self.__get(url)
		sys.stdout.write(data)

		return True

	def __upload(self):
		baseurl = 'https://c.pcs.baidu.com/rest/2.0/pcs/file'
		params = {'method':'upload','access_token':self.access_token,'path':self.args.remote_path,'ondup':'overwrite'}
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		opener = urllib2._opener
		if opener == None:
			opener = urllib2.build_opener()
			opener.add_handler(StreamingHTTPHandler())
			opener.add_handler(StreamingHTTPRedirectHandler())
			opener.add_handler(StreamingHTTPSHandler())

		urllib2.install_opener(opener)
		datagen, headers = multipart_encode({"file": open(self.args.local_path,'rb')})
		data = self.__post(url,datagen,headers)
		j = json.loads(data)
		if 'fs_id' in j:
			return True
		else:
			return False
	
	def __rapidupload(self):
		sz = os.path.getsize(self.args.local_path)
		if sz <= 256*1024:
			return False

		baseurl = 'https://pcs.baidu.com/rest/2.0/pcs/file'
		params = {'method':'rapidupload','access_token':self.access_token,'path':self.args.remote_path,'ondup':'overwrite'}
		params['content-length'] = sz
		params['content-md5'] = get_file_md5('',self.args.local_path)
		params['content-crc32'] = get_file_crc32('',self.args.local_path)
		params['slice-md5'] = get_md5(params['content-crc32'])
		url = '%s?%s' % (baseurl,urllib.urlencode(params))
		print url


def to_human_see(bytes_size):
	bytes_size = bytes_size * 1.0
	if bytes_size < 1024.0:
		return str("%.2fByte"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fKB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fMB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fGB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fTB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fPB"%bytes_size)

	return str("%.2fPB"%bytes_size)

def get_file_sha1(pre_data,filename):
	m = hashlib.sha1()
	f = open(filename)
	is_first = True
	while True:
		data = f.read(10240)
		if not data:
			break
		if is_first:
			is_first = False
			m.update(pre_data)
		m.update(data)
	return m.hexdigest()

def get_md5(data):
	m = hashlib.md5()
	m.update(str(data))
	return m.hexdigest()

def get_file_md5(pre_data,filename):
	m = hashlib.md5()
	f = open(filename)
	is_first = True
	while True:
		data = f.read(10240)
		if not data:
			break
		if is_first:
			is_first = False
			m.update(pre_data)
		m.update(data)
	return m.hexdigest()

def get_file_crc32(pre_data,filename):
	f = open(filename)
	is_first = True
	while True:
		data = f.read(10240)
		if not data:
			break
		if is_first:
			is_first = False
			crc = zlib.crc32(pre_data,0)
		crc = zlib.crc32(data,crc)
	return crc & 0xffffffff

if __name__ == '__main__':
	parser = argparse.ArgumentParser(version='1.0',description='It is a command-line tool to operate baidu pcs')
	subparsers = parser.add_subparsers(title='sub-commands',dest='command')

	# auth
	auth_parser = subparsers.add_parser('auth',help='authorize to access your account')

	# quota 
	info_parser = subparsers.add_parser('quota',help='quota info')

	# list
	list_parser = subparsers.add_parser('list',help='list file of the directory')
	list_parser.add_argument('dir_path',metavar='dir_path',help='directory to list')

	# download
	download_parser = subparsers.add_parser('download',help='download file from baidu pcs and output to screen')
	download_parser.add_argument('remote_path',metavar='remote_path',help='which to download')
	download_parser.add_argument('-g','--get',dest='get',action='store_true',help='get download url,not download')

	# upload
	upload_parser = subparsers.add_parser('upload',help='upload file to baidu pcs')
	upload_parser.add_argument('remote_path',metavar='remote_path',help='which to save')
	upload_parser.add_argument('local_path',metavar='local_path',help='which to upload')

	# rapidupload
	rapidupload_parser = subparsers.add_parser('rapidupload',help='rapid upload file to baidu pcs')
	rapidupload_parser.add_argument('remote_path',metavar='remote_path',help='which to save')
	rapidupload_parser.add_argument('local_path',metavar='local_path',help='which to upload')

	# delete
	delete_parser = subparsers.add_parser('delete',help='delete file from baidu pcs')
	delete_parser.add_argument('remote',metavar='remote_path',help='which remote file or directory to delete')

	# mkdir
	mkdir_parser = subparsers.add_parser('mkdir',help='create directory')
	mkdir_parser.add_argument('dir',metavar='dir_path',help='where directory to create')

	# move
	move_parser = subparsers.add_parser('move',help='move file')
	move_parser.add_argument('from_path',metavar='from_path',help='src file path')
	move_parser.add_argument('to_path',metavar='to_path',help='dest file path')

	# copy
	copy_parser = subparsers.add_parser('copy',help='copy file')
	copy_parser.add_argument('from_path',metavar='from_path',help='src file path')
	copy_parser.add_argument('to_path',metavar='to_path',help='dest file path')

	# share
	share_parser = subparsers.add_parser('share',help='share or cancel share file,list share file')
	group = share_parser.add_mutually_exclusive_group()
	group.add_argument('-l','--list',dest='list',action='store_true',help='list all public file')
	group.add_argument('-s',dest='share',metavar='file_path',help='which file to share')
	group.add_argument('-c',dest='cancel',metavar='file_path',help='which file to cancel share')

	if len(sys.argv) > 1:
		args = parser.parse_args()
	else:
		parser.print_help()
		parser.exit()

	pcs = BaiduPcs(args)

	try:
		pcs.run()
	except urllib2.HTTPError,e:
		if e.code == 401 and e.reason == 'UNAUTHORIZED':
			print('please authorize first')
		else:
			print('execute failed, code: ' + str(e.code) + ', reason: ' + e.reason)
