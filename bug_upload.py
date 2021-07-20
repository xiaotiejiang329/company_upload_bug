# -*- coding:utf-8 -*-
import requests
import random
import logging as logger
import os
import base64
import hashlib
import string
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from requests_toolbelt.multipart.encoder import MultipartEncoder

logger.basicConfig(level=logger.INFO)


def res_encrypt(plain, public_key):
    rsakey = RSA.importKey(str(public_key))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(bytes(plain.encode("utf8"))))
    return str(cipher_text, 'utf-8')


def md5_encrytp(plain):
    md5 = hashlib.md5()
    md5.update(plain.encode('utf-8'))
    return md5.hexdigest()


def login(url, user, passwd):
    PUBLIC_KEY_TOKEN = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNkKNoYNo3WC6wEvZIXoW00GRuYiI9o6osjtXd79VnKuPnbcTfSQi+Gg2dSYWpkNqs90c3+tQ6yyM/U0HkWo1B5eTVeJw18tcygRryOgrsqLnaTOGsLAgJ2rV8mhRfpRNtVR+b18GrddSPmVXOYPMpXXGP0Cz5GhZBu6nQ+eB7ZwIDAQAB";
    pub_key = f'-----BEGIN PUBLIC KEY-----\n{PUBLIC_KEY_TOKEN}\n-----END PUBLIC KEY-----'
    text = "userid={}&platform=4&dev=iphone"
    ciphertext = res_encrypt(text, pub_key)
    headers = {
        'Token-Cninct': ciphertext,
        'Content-Type': 'application/octet-stream; charset=UTF-8',
        'Host': 'news.cninct.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.3',
    }
    data = {"account": user,
            "account_password": md5_encrytp(passwd),
            "device_token": ''.join(random.sample(string.ascii_letters + string.digits, 44)),
            "sms_code": ""
            }
    resp = requests.post(url=url, json=data, headers=headers)
    # print(resp.text)
    if resp.status_code == 200:
        ext = resp.json().get('ext')
        result = ext.get('result')
        if result:
            userid = result[0].get('userid')
            # logger.info(userid)
            # 生成token
            token = res_encrypt(text.format(userid), pub_key)
            # logger.info(token)
        return token


# 上传图片
def upload_pic(url, token, pic_dir):
    """
    # 随机上传三张图片
    :param url:
    :param headers:
    :param pic_dir:
    :return: [
    {'file_name': '52ef3e5564ffd36ebbbb76c2cfaf1de7.png',
    'org_name': 'test2.png',
    'file_size': 3957014,
    'url': 'https://news.cninct.com/JiJianTong/jjt_dir/Suggestion/52ef3e5564ffd36ebbbb76c2cfaf1de7.png'},
    ]
    """
    headers = {
        'Token-Cninct': f'{token}',
        # 'Content-Type': 'multipart/form-data; boundary=20f8a919-1375-4478-9af3-96b17c0c1418',
        # 'Content-Length': '114077',
        'Host': 'news.cninct.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.3',
    }
    # 生成路径和文件名
    pic_paths = [(name, os.path.join(pic_dir, name)) for root, dir, files in os.walk(pic_dir) for name in files]
    fields = [("uploadFileModule", "Suggestion")]
    for pic in random.sample(pic_paths, 3):
        name, path = pic
        fields.append(("uploadFile", (name, open(path, mode='rb'), "image/png")))
    multipart_encoder = MultipartEncoder(fields=fields)
    headers['Content-Type'] = multipart_encoder.content_type
    try:
        resp = requests.post(url=url, data=multipart_encoder, headers=headers)
        if resp.status_code == 200:
            # logger.info(resp.text)
            result = resp.json().get('ext').get('result')
            return result
    except Exception as e:
        logger.info(e)
        return 'error'


def upload_bug(url, token, json):
    headers = {
        'Token-Cninct': f'{token}',
        'Content-Type': 'application/octet-stream; charset=UTF-8',
        'Host': 'news.cninct.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.3',
    }
    try:
        resp = requests.post(url=url, headers=headers, json=json)
        # print(resp.text)
        if resp.status_code == 200:
            return resp.json().get('message')
    except Exception as e:
        logger.info(e)
        return 'error'


if __name__ == '__main__':
    login_url = 'https://news.cninct.com/JiJianTong?op=Login'
    url_pic = 'https://news.cninct.com/JiJianTong?op=UploadFileModule'
    url_bug = 'https://news.cninct.com/JiJianTong?op=UploadFeedbackSuggestion'
    pic_dir = 'pics'
    user = input('账号：')
    passwd = input('密码：')
    # token_cninct = 'Od5YkZbicy45P/3YuragfWa4J9oY/Juhzos9ZszwEzzWwzPSTkZPuW6CwkV3BTt+hnvAG3KP4bLbNPmn3dKzQvaX7jbHMQ91XKqqHrnKXfmHaeLew4dTLH0hE4QomKlqzVZvxzQs70g1/VBGk9XOjomg1UMraN6aKx9v+2ZQQ2o='
    token_cninct = login(url=login_url, user=user, passwd=passwd)
    # 图片上传
    res = upload_pic(url=url_pic, token=token_cninct, pic_dir=pic_dir)
    logger.info('图片上传状态：%s', res)
    pics_path = ','.join([_['file_name'] for _ in res])
    # bug提交
    payload = {"suggestion": "nothing to say", "suggestion_article_id_union": 0, "suggestion_article_type": 0,
               "suggestion_device": "MI 9", "suggestion_device_version": "安卓7.1.2",
               "suggestion_pic": f"{pics_path}",
               "suggestion_tel": "", "suggestion_type": 0, "suggestion_version": "5.1.2"}
    msg = upload_bug(url=url_bug, token=token_cninct, json=payload)
    # print(msg)
    logger.info('bug上传状态：%s', msg)
    # print(res)
    # pic_paths = [os.path.join(pic_dir, name) for root, dir, files in os.walk(pic_dir) for name in files]
    # three_path = random.sample(pic_paths, 3)
    # print(three_path[])
