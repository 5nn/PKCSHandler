//
//  PKCService.m
//  PKCSHandler
//
//  Created by mike on 20/7/2017.
//  Copyright © 2017 mike. All rights reserved.
//

#import "PKCService.h"

@implementation PKCService

+(BOOL)saveIdentity:(SecIdentityRef)identity withKey:(NSString *)key{
    SecIdentityRef myIdentity = [PKCService getIdentityWithKey:key];
    if (myIdentity) {
        CFRelease(myIdentity);
        [PKCService deleteIdentityWithKey:key];
        
    }
    CFTypeRef  identity_handle = NULL;
    const void *keys[] =   { kSecReturnPersistentRef, kSecValueRef , kSecAttrLabel};
    const void *values[] = { kCFBooleanTrue, identity, (__bridge CFStringRef)key};
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 3, NULL, NULL);
    // Add the key chain information
    OSStatus status = SecItemAdd(dict, &identity_handle);
    if (dict) {
        CFRelease(dict);
    }
    if (identity_handle) {
        CFRelease(identity_handle);
    }
    if(status == noErr){
        return YES;
    }
    else {
        return NO;
    }
}

+(SecIdentityRef)getIdentityWithKey:(NSString *)key{
    CFTypeRef   identity_ref = NULL;
    
    const void *keys[] = { kSecClass, kSecAttrLabel , kSecReturnRef};
    const void *values[] = { kSecClassIdentity, (__bridge CFStringRef)key ,kCFBooleanTrue};
    @try {
        CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 3, NULL, NULL);
        OSStatus status = SecItemCopyMatching(dict, &identity_ref);
        if(dict) CFRelease(dict);
        if(status == noErr){
            return (SecIdentityRef)identity_ref;
        }
        else
        {
            return nil;
        }
    }
    @catch (NSException * e) {
        
    }
    return nil;
}

+(BOOL)deleteIdentityWithKey:(NSString *)key{
    const void *keys[] =   { kSecClass, kSecAttrLabel};
    const void *values[] = { kSecClassIdentity, (__bridge CFStringRef)key};
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 2, NULL, NULL);
    OSStatus status = SecItemDelete(dict);
    if(dict) CFRelease(dict);
    if(status == noErr){
        return YES;
    }else{
        return NO;
    }
}

+(SecKeyRef)getPrivateKeyFromIdentity:(SecIdentityRef)identity{
    SecKeyRef privateKey =NULL;
    OSStatus status = SecIdentityCopyPrivateKey(identity, &privateKey);
    if(status == noErr){
        return privateKey;
    }else{
        return nil;
    }
}

+(NSData *)getCertDataFromIdentity:(SecIdentityRef)identity{
    SecCertificateRef pCert = nil;
    OSStatus status = SecIdentityCopyCertificate(identity, &pCert);
    CFDataRef CertData = SecCertificateCopyData(pCert);
    if(status == noErr){
        CFRelease(pCert);
        // Modify by Fish 20110505
        //NSData *nsdRT = (NSData *)CertData;
        //[nsdRT autorelease];
        //CFRelease(CertData);
        
        return (__bridge NSData *)CertData;
        //return nsdRT;
    }
    else {
        CFRelease(CertData);
        
        return nil;
    }
}

+(NSString*)getCertNameFromIdentity:(SecIdentityRef)identity{
    SecCertificateRef pCert = nil;
    OSStatus status = SecIdentityCopyCertificate(identity,&pCert);
    if(status == noErr){
        CFStringRef MyName = SecCertificateCopySubjectSummary(pCert);
        CFRelease(pCert);
        // Modify by Fish 20110505
        //NSString *nstrRT = [[NSString alloc] initWithString:(NSString *)MyName];
        //NSString *nstrRT = (NSString *)MyName;
        //CFRelease(MyName);
        
        return (__bridge NSString *)MyName;
        //return nstrRT;
    }
    else {
        return nil;
    }
}

+(BOOL)savePublicKey:(SecKeyRef)key withKey:(NSString *)key_{
    CFTypeRef  handle = NULL;
    
    const void *keys[] =   { kSecReturnPersistentRef, kSecValueRef , kSecAttrLabel};
    const void *values[] = { kCFBooleanTrue,          key , (__bridge CFStringRef)key_};
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 3, NULL, NULL);
    
    OSStatus status=SecItemAdd(dict, &handle);
    
    if(dict) CFRelease(dict);
    if(handle) CFRelease(handle);
    
    if(status == noErr){
        return YES;
    }else{
        return NO;
    }
}
+(BOOL)deletePublicKey:(NSString *)label{
    const void *keys[] =   { kSecClass, kSecAttrLabel };
    const void *values[] = { kSecClassKey, (__bridge CFStringRef)label };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 2, NULL, NULL);
    OSStatus status = SecItemDelete(dict);
    if(dict) CFRelease(dict);
    if(status == noErr){
        return YES;
    }else{
        return NO;
    }
}
+(SecKeyRef)getPublicKey:(NSString *)label{
    CFTypeRef   ref     = NULL;
    const void *keys[] =   { kSecClass, kSecAttrLabel , kSecReturnRef};
    const void *values[] = { kSecClassKey, (__bridge CFStringRef)label ,kCFBooleanTrue};
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, 3, NULL, NULL);
    OSStatus status=SecItemCopyMatching(dict, &ref);
    if(dict) CFRelease(dict);
    if(status == noErr){
        return (SecKeyRef)ref;
    }else{
        return nil;
    }
}

+(void)printIdentitySummary:(SecIdentityRef)identity{
    SecCertificateRef myReturnedCertificate = NULL;
    OSStatus status = SecIdentityCopyCertificate(identity, &myReturnedCertificate);
    if(status == 0){
        CFStringRef certSummary = SecCertificateCopySubjectSummary(myReturnedCertificate);
        NSString *summaryString = [[NSString alloc] initWithString:(__bridge NSString*)certSummary];
        // Add by Fish 20110503
        CFRelease(certSummary);
        
        summaryString = nil;
    }
    if(myReturnedCertificate) CFRelease(myReturnedCertificate);
}

+(NSData *)encrypt:(NSString *)plainText usingKey:(SecKeyRef)key{
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = NULL;
    cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus status = SecKeyEncrypt(key, kSecPaddingNone,
                                    (const uint8_t *)[plainTextBytes bytes],
                                    [plainTextBytes length], cipherBuffer,
                                    &cipherBufferSize);
    
    NSData *encryptedBytes = nil;
    if(status == noErr){
        //NSLog(@"encrypted text: %s", cipherBuffer);
        encryptedBytes = [[NSData alloc]
                           initWithBytes:(const void *)cipherBuffer
                           length:cipherBufferSize];
        //NSLog(@"Encrypted text (%d bytes): %@",
        //	  [encryptedBytes length], [encryptedBytes description]);
    }
    if(cipherBuffer) free(cipherBuffer);
    return encryptedBytes;
}

+(NSData *)decrypt:(NSData *)data withKey:(SecKeyRef)key {
    // Comment by Fish 20110505
    //uint8_t *cip = NULL;
    //cip = (uint8_t *)[data bytes];
    size_t plainBufferSize = SecKeyGetBlockSize(key);
    uint8_t *plainBuffer = malloc(plainBufferSize * sizeof(uint8_t));
    OSStatus status = SecKeyDecrypt(key,
                                    kSecPaddingNone,
                                    (uint8_t *)[data bytes],
                                    [data length],
                                    plainBuffer,
                                    &plainBufferSize
                                    );
    NSData *retData = nil;
    if(status == noErr) {
        retData = [[NSData alloc] initWithBytes:(const void *)plainBuffer length:plainBufferSize] ;
        
        return retData;
    }
    if(plainBuffer) {
        free(plainBuffer);
    }
    
    return retData;
}

+(NSData *)signDataInPKCS1SHA1:(NSData *)data withPrivateKey:(SecKeyRef)key{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    
    size_t sigBufferSize = SecKeyGetBlockSize(key);
    uint8_t *sigBuffer=NULL;
    sigBuffer = malloc(sigBufferSize * sizeof(uint8_t));
    
    OSStatus status = SecKeyRawSign(key, kSecPaddingPKCS1SHA1,
                                    digest,
                                    sizeof(digest),
                                    sigBuffer, &sigBufferSize);
    //NSLog(@"Sign Status:%d",status);
    NSData *encryptedBytes = nil;
    if(status == noErr){
        encryptedBytes = [[NSData alloc]
                           initWithBytes:(const void *)sigBuffer
                           length:sigBufferSize];
    }
    if(sigBuffer) free(sigBuffer);
    return encryptedBytes;
}



+(BOOL)verifyDataInPKCS1SHA1:(NSData *)data forSignature:(NSData *)sigData withPublicKey:(SecKeyRef)key{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    
    OSStatus status = SecKeyRawVerify(key, 
                                      kSecPaddingPKCS1SHA1, 
                                      digest, 
                                      sizeof(digest), 
                                      (const uint8_t *)[sigData bytes], 
                                      [sigData length]);
    //NSLog(@"Verify Status:%d",status);
    if(status == noErr){
        return YES;
    }else{
        return NO;
    }
}

+(NSData *)signHash:(uint8_t *)hasInput withPrivateKey:(SecKeyRef)key{
    size_t sigBufferSize = SecKeyGetBlockSize(key);
    uint8_t *sigBuffer=NULL;
    sigBuffer = malloc(sigBufferSize * sizeof(uint8_t));
    
    //uint8_t *hashBytes = nil;	
    //hashBytes = [initWithBytes:(const void *)hasInput 
    //length:CC_SHA1_DIGEST_LENGTH] ;
    
    size_t hasInputSize = CC_SHA1_DIGEST_LENGTH;
    OSStatus status = SecKeyRawSign(key, kSecPaddingPKCS1SHA1, 
                                    hasInput, 
                                    hasInputSize, 
                                    sigBuffer, &sigBufferSize);
    
    NSData *encryptedBytes = nil;
    if(status == noErr){
        encryptedBytes = [[NSData alloc]
                           initWithBytes:(const void *)sigBuffer 
                           length:sigBufferSize];
        
    }
    
    return encryptedBytes;
    
}
#pragma mark -
#pragma mark Memory management
-(void)dealloc{
    
}


@end
