//
//  PKCService.h
//  PKCSHandler
//
//  Created by mike on 20/7/2017.
//  Copyright © 2017 mike. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

@interface PKCService : NSObject

+(BOOL)saveIdentity:(SecIdentityRef)identity withKey:(NSString *)key;
+(SecIdentityRef)getIdentityWithKey:(NSString *)key;
+(BOOL)deleteIdentityWithKey:(NSString *)key;

+(SecKeyRef)getPrivateKeyFromIdentity:(SecIdentityRef)identity;
+(NSData *)getCertDataFromIdentity:(SecIdentityRef)identity;
+(NSString*)getCertNameFromIdentity:(SecIdentityRef)identity;
+(BOOL)savePublicKey:(SecKeyRef)key withKey:(NSString *)key_;
+(BOOL)deletePublicKey:(NSString *)key;
+(SecKeyRef)getPublicKey:(NSString *)key;

+(void)printIdentitySummary:(SecIdentityRef)identity;

+(NSData *)encrypt:(NSString *)plainText usingKey:(SecKeyRef)key;
+(NSData *)decrypt:(NSData *)data withKey:(SecKeyRef)key;

+(NSData *)signDataInPKCS1SHA1:(NSData *)data withPrivateKey:(SecKeyRef)key;
+(NSData *)signHash:(uint8_t *)hasInput withPrivateKey:(SecKeyRef)key;
+(BOOL)verifyDataInPKCS1SHA1:(NSData *)data forSignature:(NSData *)sigData withPublicKey:(SecKeyRef)key;

@end
