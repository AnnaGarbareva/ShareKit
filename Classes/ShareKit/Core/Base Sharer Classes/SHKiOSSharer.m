//
//  SHKiOSSharerViewController.m
//  ShareKit
//
//  Created by Vilem Kurz on 18/11/2012.
//
//

#import "SHKiOSSharer_Protected.h"
#import "SharersCommonHeaders.h"
#import "UIApplication+iOSVersion.h"
#import <Social/Social.h>

@interface SHKiOSSharer ()

/**
* Due to the bug in ios SDK we need to keep reference to ACAccountStore.
*/
@property (nonatomic, strong) ACAccountStore * accountStore;

@end

@implementation SHKiOSSharer

#pragma mark - Abstract methods

- (NSString *)accountTypeIdentifier {
    
    NSAssert(NO, @"Abstract method. Must be subclassed!");
    return nil;
}

- (NSString *)serviceTypeIdentifier {
    
    NSAssert(NO, @"Abstract method. Must be subclassed!");
    return nil;
}

#pragma mark - UI

- (void)show
{
    [self doIfOnline:^{
        if ([SHKCONFIG(useAppleShareUI) boolValue]) {

            BOOL nativeUISuccessful = [self shareWithServiceType:[self serviceTypeIdentifier]];
            if (nativeUISuccessful) return; //shared via iOS native UI
        }

        [super show];
    } orFail:^{
        [self sendDidOfflineFail];
    }];
}

- (BOOL)shareWithServiceType:(NSString *)serviceType {
    
    if (self.item.shareType == SHKShareTypeFile || self.item.shareType == SHKShareTypeUserInfo) return NO;
    
    SLComposeViewController *sharerUIController = [SLComposeViewController composeViewControllerForServiceType:serviceType];
    
    if (self.item.image) {
        BOOL addedImage = [sharerUIController addImage:self.item.image];
        if (!addedImage) return NO;
    }

    if (self.item.URL) {
        BOOL addedURL = [sharerUIController addURL:self.item.URL];
        if (!addedURL) return NO;
    }
    
    NSString *initialText = (self.item.shareType == SHKShareTypeText ? self.item.text : self.item.title);
    
    NSString *tagString = [self joinedTags];
    if ([tagString length] > 0) initialText = [initialText stringByAppendingFormat:@" %@",tagString];

        
    NSUInteger textLength = [initialText length];
    
    while ([sharerUIController setInitialText:[initialText substringToIndex:textLength]] == NO && textLength > 0) {
        textLength--;
    }
    
    sharerUIController.completionHandler = ^(SLComposeViewControllerResult result)
    {
        
        if ([[UIApplication sharedApplication] isiOS6OrOlder]) {
            [[SHK currentHelper] hideCurrentViewControllerAnimated:YES];
        } else {
            [[SHK currentHelper] setCurrentView:nil];
        }
        
        switch (result) {
                
            case SLComposeViewControllerResultDone:
                [self sendDidFinish];
                break;
                
            case SLComposeViewControllerResultCancelled:
                [self sendDidCancel];
                
            default:
                break;
        }
    };
    
    [[SHK currentHelper] showStandaloneViewController:sharerUIController];
    return YES;
}

#pragma mark - Authorization

- (BOOL)isAuthorized {
    
    ACAccountType *accountType = [self.accountStore accountTypeWithAccountTypeIdentifier:[self accountTypeIdentifier]];
    BOOL result = accountType.accessGranted;
    
    if (!result) [[self class] logout]; //destroy userInfo
    
    return result;
}

- (void)authorizationFormShow {
    
    ACAccountType *sharerAccountType = [self.accountStore accountTypeWithAccountTypeIdentifier:[self accountTypeIdentifier]];

    [self.accountStore requestAccessToAccountsWithType:sharerAccountType
                                   options:nil
                                completion:^(BOOL granted, NSError *error) {

                                    [self authDidFinish:granted];

                                    if (granted) {
                                        [self tryPendingAction];
                                    } else {
                                        [self iOSAuthorizationFailedWithError:error];
                                        [[self class] logout];
                                    }
                                }];
}

- (void)iOSAuthorizationFailedWithError:(NSError *)error {
    
    if (!error) {
        [self authDidFinishWithError:[self newErrorWhenRevokedAccess]];
    } else if ([error.domain isEqualToString:ACErrorDomain]){

        switch (error.code) {
            case ACErrorAccountNotFound: //code ACErrorAccountNotFound means user account not exists in settings.app
                [self authDidFinishWithError:[self newErrorWhenAccountNotFound]];
                break;
            case ACErrorAccessInfoInvalid:
                NSAssert(NO, @"Missing %@ app id - set it in your configurator", [self sharerTitle]);
                break;
            default:
                //code 7 user just has not allowed access - no need to show alert. //what about other error codes?
                break;
        }
    }
    SHKLog(@"auth failed:%@", [error description]);

    [[self class] logout];
}

- (void)iOSAuthorizationFinished
{
    [self authDidFinishWithError:nil];
}

#pragma mark - Authorization helpers

- (NSArray *)availableAccounts {
    
    ACAccountType *twitterAccountType = [self.accountStore accountTypeWithAccountTypeIdentifier:[self accountTypeIdentifier]];
    NSArray *result = [self.accountStore accountsWithAccountType:twitterAccountType];
    return result;
}

- (NSError *)newErrorWhenAccountNotFound
{
    NSMutableDictionary *userInfo = [NSMutableDictionary new];
    userInfo[SHKErrorTitleKey] = SHKLocalizedString(@"No %@ Accounts", [[self class] sharerTitle]);
    userInfo[NSLocalizedDescriptionKey] = SHKLocalizedString(@"There are no %@ accounts configured. You can add or create a %@ account in Settings.", [[self class] sharerTitle], [[self class] sharerTitle]);
    return [NSError errorWithDomain:SHKErrorDomain code:SHKErrorCodeAccessDenied userInfo:userInfo];
}

- (NSError *)newErrorWhenRevokedAccess
{
    NSMutableDictionary *userInfo = [NSMutableDictionary new];
    userInfo[SHKErrorTitleKey] = SHKLocalizedString(@"No %@ Accounts", [[self class] sharerTitle]);
    userInfo[NSLocalizedDescriptionKey] = SHKLocalizedString(@"Access to %@ is not allowed for this app. You can allow access in Settings.", [[self class] sharerTitle]);
    return [NSError errorWithDomain:SHKErrorDomain code:SHKErrorCodeAccessDenied userInfo:userInfo];
}

#pragma mark - MISC

- (NSString *)joinedTags {
    
    return nil;
}

#pragma mark - ACAccountStore lazy loading

- (ACAccountStore *)accountStore {
    if (!_accountStore) {
        _accountStore = [[ACAccountStore alloc] init];
    }
    return _accountStore;
}


@end
