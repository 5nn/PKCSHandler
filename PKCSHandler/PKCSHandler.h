//
//  PKCSHandler.h
//  PKCSHandler
//
//  Created by mike on 20/7/2017.
//  Copyright © 2017 mike. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
@interface PKCSHandler : NSObject

/**
 *@breif 从证书文件中读取信息
 *
 *@param path certificate path
 *
 *@param passwd 密码
 */
-(BOOL)readP12FromFilePath:(NSString *)path withPassword:(NSString *)passwd;

/**
 *@breif 从证书文件中读取信息
 *
 *@param PKCS12Data certificate data
 *
 *@param passwd 密码
 */
-(BOOL)readP12FromData:(NSData *)PKCS12Data withPassword:(NSString *)passwd;

/** 获取证书相关特征 **/
-(SecIdentityRef)getIdentity;
-(SecTrustRef)getTrust;
-(SecKeyRef)getPublicKey;
-(SecKeyRef)getPrivateKey;

/** 获取证书数据 **/
-(NSData *)getCertData;

@end
