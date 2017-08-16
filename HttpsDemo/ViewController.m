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


}

- (IBAction)singleAuth:(id)sender forEvent:(UIEvent *)event {
    
    [self test1];
}


- (IBAction)doubleAuth:(id)sender forEvent:(UIEvent *)event {
    
    [[UIAHttps shared]  get:@"/" params:nil success:^(id obj) {
        NSString *resStr = [[NSString alloc] initWithData:obj encoding:NSUTF8StringEncoding];
        NSLog(@"%@", resStr);
    } failure:^(NSError *err) {
        NSLog(@"%@", err);
    }];
    
}

- (IBAction)httpGet:(id)sender {
    NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"http://api.onezen.cc"]];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"%@",str);
}




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
    
    [self get:@"/" params:nil success:^(id obj) {
        NSString *resStr = [[NSString alloc] initWithData:obj encoding:NSUTF8StringEncoding];
        NSLog(@"%@", resStr);
    } failure:^(NSError *err) {
        
    }];
}

- (void)get:(NSString *)url params:(NSDictionary *)params success:(void (^)(id obj))success failure:(void (^)(NSError * err))failure {
    // 1.获得请求管理者
    AFHTTPSessionManager *mgr = [[AFHTTPSessionManager alloc] initWithBaseURL:[NSURL URLWithString:@"https://www.onezen.cc/"]];
    
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
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"www.onezen.cc" ofType:@"cer"];//证书的路径
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

