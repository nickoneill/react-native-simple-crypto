#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

#import "Shared.h"
#import "Hmac.h"

@implementation Hmac

+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [Shared fromHex:key];
    NSData* inputData = [Shared fromHex:input];
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];

    // Added convert to hex string
    NSUInteger capacity = nsdata.length * 2;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:capacity];
    const unsigned char *buf = nsdata.bytes;
    NSInteger i;
    for (i=0; i<nsdata.length; ++i) {
      [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }

    return [Shared toHex:sbuf];
}

@end
