//
//  ViewController.m
//  HttpsDemo
//
//  Created by leaf on 2017/8/15.
//  Copyright © 2017年 cc.onezen. All rights reserved.
//

#import "ViewController.h"
#import "AFNetworking.h"
#import "UIAHttps.h"

@interface ViewController ()

@property (nonatomic, strong) NSMutableData *mData;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    
//    [self getDataWithURLRequest];
//
//    https://101.201.232.5/dcms/PwasAdmin/AreaKh-getCaseType.action
    [[UIAHttps shared]  get:@"/" params:nil success:^(id obj) {
        NSString *resStr = [[NSString alloc] initWithData:obj encoding:NSUTF8StringEncoding];
        NSLog(@"%@", resStr);
    } failure:^(NSError *err) {
        NSLog(@"%@", err);
    }];
}





- (void)getDataWithURLRequest {
    //connection
    NSString *urlStr = @"https://api.onezen.cc";
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];
    NSURLConnection *connection = [[NSURLConnection alloc]initWithRequest:request delegate:self];
    [connection start];
}


- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    
    /*
     //直接验证服务器是否被认证（serverTrust），这种方式直接忽略证书验证，直接建立连接，但不能过滤其它URL连接，可以理解为一种折衷的处理方式，实际上并不安全，因此不推荐。
     SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
     return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
     forAuthenticationChallenge: challenge];
     */
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust]) {
        do
        {
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            NSCAssert(serverTrust != nil, @"serverTrust is nil");
            if(nil == serverTrust)
                break; /* failed */
            /**
             *  导入多张CA证书（Certification Authority，支持SSL证书以及自签名的CA）
             */
            NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"cer"];//自签名证书
            NSData* caCert = [NSData dataWithContentsOfFile:cerPath];
            
            NSString *cerPath2 = [[NSBundle mainBundle] pathForResource:@"server1" ofType:@"cer"];//SSL证书
            NSData * caCert2 = [NSData dataWithContentsOfFile:cerPath2];
            
            NSCAssert(caCert != nil, @"caCert is nil");
            if(nil == caCert)
                break; /* failed */
            
            NSCAssert(caCert2 != nil, @"caCert2 is nil");
            if (nil == caCert2) {
                break;
            }
            
            SecCertificateRef caRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caCert);
            NSCAssert(caRef != nil, @"caRef is nil");
            if(nil == caRef)
                break; /* failed */
            
            SecCertificateRef caRef2 = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caCert2);
            NSCAssert(caRef2 != nil, @"caRef2 is nil");
            if(nil == caRef2)
                break; /* failed */
            
            NSArray *caArray = @[(__bridge id)(caRef),(__bridge id)(caRef2)];
            
            NSCAssert(caArray != nil, @"caArray is nil");
            if(nil == caArray)
                break; /* failed */
            
            OSStatus status = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)caArray);
            NSCAssert(errSecSuccess == status, @"SecTrustSetAnchorCertificates failed");
            if(!(errSecSuccess == status))
                break; /* failed */
            
            SecTrustResultType result = -1;
            status = SecTrustEvaluate(serverTrust, &result);
            if(!(errSecSuccess == status))
                break; /* failed */
            NSLog(@"stutas:%d",(int)status);
            NSLog(@"Result: %d", result);
            
            BOOL allowConnect = (result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed);
            if (allowConnect) {
                NSLog(@"success");
            }else {
                NSLog(@"error");
            }
            /* https://developer.apple.com/library/ios/technotes/tn2232/_index.html */
            /* https://developer.apple.com/library/mac/qa/qa1360/_index.html */
            /* kSecTrustResultUnspecified and kSecTrustResultProceed are success */
            if(! allowConnect)
            {
                break; /* failed */
            }
            
#if 0
            /* Treat kSecTrustResultConfirm and kSecTrustResultRecoverableTrustFailure as success */
            /*   since the user will likely tap-through to see the dancing bunnies */
            if(result == kSecTrustResultDeny || result == kSecTrustResultFatalTrustFailure || result == kSecTrustResultOtherError)
                break; /* failed to trust cert (good in this case) */
#endif
            
            // The only good exit point
            return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
                          forAuthenticationChallenge: challenge];
            
        } while(0);
    }
    
    // Bad dog
    return [[challenge sender] cancelAuthenticationChallenge: challenge];
    
}
//这里的关键在于result参数的值，根据官方文档的说明，判断(result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed)的值，若为1，则该网站的CA被app信任成功，可以建立数据连接，这意味着所有由该CA签发的各个服务器证书都被信任，而访问其它没有被信任的任何网站都会连接失败。该CA文件既可以是SLL也可以是自签名。
//
//NSURLConnection的其它代理方法实现


#pragma mark -- connect的异步代理方法
-(void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    NSLog(@"请求被响应");
    _mData = [[NSMutableData alloc]init];
}

-(void)connection:(NSURLConnection *)connection didReceiveData:(nonnull NSData *)data {
    NSLog(@"开始返回数据片段");
    
    [_mData appendData:data];
}

-(void)connectionDidFinishLoading:(NSURLConnection *)connection {
    NSLog(@"链接完成");
    //可以在此解析数据
    NSString *receiveInfo = [NSJSONSerialization JSONObjectWithData:self.mData options:NSJSONReadingAllowFragments error:nil];
    NSLog(@"received data:\\\\n%@",[[NSString alloc] initWithData:_mData encoding:NSUTF8StringEncoding]);
    NSLog(@"received info:\\\\n%@",receiveInfo);
}

//链接出错
-(void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    NSLog(@"error - %@",error);
}


//***************************************************************************************

- (void)test1{
    
    [self get:@"/v1/video/list" params:nil success:^(id obj) {
        NSString *resStr = [[NSString alloc] initWithData:obj encoding:NSUTF8StringEncoding];
        NSLog(@"%@", resStr);
    } failure:^(NSError *err) {
        
    }];
}

- (void)get:(NSString *)url params:(NSDictionary *)params success:(void (^)(id obj))success failure:(void (^)(NSError * err))failure {
    // 1.获得请求管理者
    AFHTTPSessionManager *mgr = [[AFHTTPSessionManager alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.onezen.cc/"]];
    
    // 2.申明返回的结果是text/html类型
    mgr.responseSerializer = [AFHTTPResponseSerializer serializer];
    // 3.设置超时时间为10s
    mgr.requestSerializer.timeoutInterval = 10;
    
    // 加上这行代码，https ssl 验证。
    [mgr setSecurityPolicy:[self customSecurityPolicy]];
    
    // 4.发送GET请求
    
    [mgr GET:url parameters:params progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        if (success) {
            success(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        if (failure) {
            failure(error);
        }
    }];

}

- (AFSecurityPolicy*)customSecurityPolicy {
    // /先导入证书
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"api.onezen.cc" ofType:@"cer"];//证书的路径
    NSData *certData = [NSData dataWithContentsOfFile:cerPath];
    
    
    
    // AFSSLPinningModeCertificate 使用证书验证模式
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    // allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
    // 如果是需要验证自建证书，需要设置为YES
    securityPolicy.allowInvalidCertificates = YES;
    
    //validatesDomainName 是否需要验证域名，默认为YES；
    //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    //置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    //如置为NO，建议自己添加对应域名的校验逻辑。
    securityPolicy.validatesDomainName = NO;
    
    securityPolicy.pinnedCertificates = [NSSet setWithObject:certData];
    
    return securityPolicy;
}

@end

