//
//  PKCSHandler.m
//  PKCSHandler
//
//  Created by mike on 20/7/2017.
//  Copyright © 2017 mike. All rights reserved.
//

#import "PKCSHandler.h"

@interface PKCSHandler ()

@property (nonatomic, strong) NSDictionary *myIdentityAndTrust;

@end

@implementation PKCSHandler


-(BOOL)readP12FromFilePath:(NSString *)path withPassword:(NSString *)passwd{
    NSData *PKCSData = [[NSData alloc] initWithContentsOfFile:path];
    BOOL bReadP12=[self readP12FromData:PKCSData withPassword:passwd];
   
    return bReadP12;
}


-(BOOL)readP12FromData:(NSData *)PKCS12Data withPassword:(NSString *)passwd {
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef password = (__bridge CFStringRef)passwd;
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {password};
    
    CFDictionaryRef optionsDiectionary = CFDictionaryCreate(NULL, keys, values
                                                            , 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDiectionary, &items);
    if(status == noErr){
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        self.myIdentityAndTrust = (__bridge NSDictionary *)myIdentityAndTrust;
    }
    if(optionsDiectionary) {
        CFRelease(optionsDiectionary);
    }
    if(status == noErr){
        return YES;
    } 	else{
        return NO;
    }
}

-(SecIdentityRef)getIdentity{
    if(self.myIdentityAndTrust != nil)
        return (__bridge SecIdentityRef)[self.myIdentityAndTrust objectForKey:(NSString *)kSecImportItemIdentity];
    else
        return nil;
}
-(SecTrustRef)getTrust{
    if(self.myIdentityAndTrust==nil) return nil;
    return (__bridge SecTrustRef)[self->_myIdentityAndTrust objectForKey:(NSString *)kSecImportItemTrust];
}
-(SecKeyRef)getPublicKey{
    if(self.myIdentityAndTrust == nil) return nil;
    SecTrustRef trust = [self getTrust];
    SecKeyRef k = SecTrustCopyPublicKey(trust);
    //CFRelease(trust);
    return k;
}
-(SecKeyRef)getPrivateKey{
    if(self.myIdentityAndTrust == nil) return nil;
    SecIdentityRef identity = [self getIdentity];
    SecKeyRef privateKey = nil;
    OSStatus status = SecIdentityCopyPrivateKey(identity, &privateKey);
    //CFRelease(identity);
    if(status == noErr){
        return privateKey;
    }else{
        return nil;
    }
}
-(NSData *)getCertData{
    SecIdentityRef identity = [self getIdentity];
    SecCertificateRef pCert = nil;
    OSStatus status = SecIdentityCopyCertificate(identity,&pCert);
    CFDataRef CertData = SecCertificateCopyData(pCert);
  
    CFRelease(pCert);
    CFRelease(identity);
    if(status == noErr){
        return (__bridge NSData *)CertData;
      
    }
    else {
     
        CFRelease(CertData);
        return nil;
    }
    
}

#pragma mark -
#pragma mark Memory management
-(void)dealloc{
    
    self->_myIdentityAndTrust = nil;
   
}



@end
