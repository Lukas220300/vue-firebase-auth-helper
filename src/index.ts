import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword } from "firebase/auth";
import { initializeApp, FirebaseApp } from "firebase/app";
import {Axios} from "axios";

export default class VueFirebaseAuth {

    protected apiKey: string
    protected authDomain: string
    protected projectId: string
    protected storageBucket: string
    protected messagingSenderId: string
    protected appId: string

    protected firebaseApp: FirebaseApp

    protected static accessTokenKey = 'access_token'
    protected static refreshTokenKey = 'refresh_token'
    protected static userKey = 'user'
    protected static accessTokenExpireKey = 'access_token_expires_at'

    protected httpClient: Axios

    protected localStorage: any

    constructor(apiKey:string, authDomain:string, projectId:string, storageBucket:string, messagingSenderId:string, appId:string, httpClient:Axios) {
        this.apiKey = apiKey
        this.authDomain = authDomain
        this.projectId = projectId
        this.storageBucket = storageBucket
        this.messagingSenderId = messagingSenderId
        this.appId = appId

        this.firebaseApp = initializeApp({
            apiKey: this.apiKey,
            authDomain: this.authDomain,
            projectId: this.projectId,
            storageBucket: this.storageBucket,
            messagingSenderId: this.messagingSenderId,
            appId: this.appId,
        })
        this.httpClient = httpClient

        this.localStorage = this.buildLocalStorageObject()
    }

    getFirebaseConfiguration () {
        return {
            apiKey: this.apiKey,
            authDomain: this.authDomain,
            projectId: this.projectId,
            storageBucket: this.storageBucket,
            messagingSenderId: this.messagingSenderId,
            appId: this.appId,
        }
    }

    getCurrentTimeStamp() {
        return Math.round(new Date().getTime()/1000)
    }

    buildLocalStorageObject() {
        return {
            accessToken: {
                setAccessToken: (accessToken: string, expiresIn:any) => {
                    window.localStorage.setItem(VueFirebaseAuth.accessTokenKey, accessToken)
                    window.localStorage.setItem(VueFirebaseAuth.accessTokenExpireKey, (String)(this.getCurrentTimeStamp() + parseInt(expiresIn)))
                },
                clearAccessToken: () => {
                    window.localStorage.removeItem(VueFirebaseAuth.accessTokenKey)
                    window.localStorage.removeItem(VueFirebaseAuth.accessTokenExpireKey)
                },
                getAccessToken: () => {
                    return window.localStorage.getItem(VueFirebaseAuth.accessTokenKey)
                },
                getExpireTimeStamp: () => {
                    return window.localStorage.getItem(VueFirebaseAuth.accessTokenExpireKey)
                }
            },
            refreshToken: {
                setRefreshToken: (refreshToken: string) => {
                    window.localStorage.setItem(VueFirebaseAuth.refreshTokenKey, refreshToken)
                },
                clearRefreshToken: () => {
                    window.localStorage.removeItem(VueFirebaseAuth.refreshTokenKey)
                },
                getRefreshToken : () => {
                    return window.localStorage.getItem(VueFirebaseAuth.refreshTokenKey)
                },
            },
            user: {
                setUser: (userObject: object) => {
                    window.localStorage.setItem(VueFirebaseAuth.userKey, JSON.stringify(userObject))
                },
                clearUser: () => {
                    window.localStorage.removeItem(VueFirebaseAuth.userKey)
                },
                getUser: () => {
                    const userJson = window.localStorage.getItem(VueFirebaseAuth.userKey)
                    if(userJson) {
                        return JSON.parse(userJson)
                    }
                    return userJson;
                }
            },
            clearAccessData: () => {
                this.localStorage.accessToken.clearAccessToken()
                this.localStorage.refreshToken.clearRefreshToken()
                this.localStorage.user.clearUser()
            }
        }
    }

    login(username:string, password:string, onSuccess:any, onError:any) {
        const auth = getAuth();
        signInWithEmailAndPassword(auth, username, password)
            .then((userCredential:any) => {
                this.handleUserCredential(userCredential)
                onSuccess(userCredential.user)
            })
            .catch((error) => {
                onError(error)
            });
    }

    register(username:string, password:string, onSuccess:any, onError:any) {
        const auth = getAuth();
        createUserWithEmailAndPassword(auth,username,password)
            .then((userCredential:any) => {
                this.handleUserCredential(userCredential)
                onSuccess(userCredential.user)
            })
            .catch((error:any) => {
                onError(error)
            })

    }

    handleUserCredential(userCredential: any) {
        this.localStorage.accessToken.setAccessToken(userCredential._tokenResponse.idToken, userCredential._tokenResponse.expiresIn)
        this.localStorage.refreshToken.setRefreshToken(userCredential._tokenResponse.refreshToken)

        const user = {
            email : userCredential.user.email,
            displayName : userCredential.user.displayName,
            emailVerified : userCredential.user.emailVerified,
            isAnonymous : userCredential.user.isAnonymous,
            metadata : userCredential.user.metadata,
            phoneNumber : userCredential.user.phoneNumber,
            photoURL : userCredential.user.photoURL,
            providerId : userCredential.user.providerId,
            uid : userCredential.user.uid,
        }
        this.localStorage.user.setUser(user)
    }

    getUser() {
        this.validateAccessData()
        return this.localStorage.user.getUser();
    }

    validateAccessData() {
        if(
            !this.localStorage.accessToken.getAccessToken() ||
            !this.localStorage.accessToken.getExpireTimeStamp() ||
            this.localStorage.accessToken.getExpireTimeStamp() <= this.getCurrentTimeStamp()||
            this.localStorage.accessToken.getAccessToken() === 'undefined' ||
            this.localStorage.accessToken.getExpireTimeStamp() === 'NaN'
        ) {
            this.refreshAccessTokenWithRefreshToken()
                .then(successfully => {
                    if(!successfully) {
                        this.localStorage.clearAccessData()
                    }
                })
        }
    }

    async refreshAccessTokenWithRefreshToken() {
        const refreshToken = this.localStorage.refreshToken.getRefreshToken()
        if(!refreshToken || refreshToken === 'NaN') {
            return false
        }
        return await this.httpClient.post('https://securetoken.googleapis.com/v1/token?key=' + this.apiKey, {
            grant_type : 'refresh_token',
            refresh_token : refreshToken,
        }).then((response:any) => {
            this.localStorage.accessToken.setAccessToken(response.access_token, response.expires_in)
            this.localStorage.refreshToken.setRefreshToken(response.refresh_token)
            return true
        })
            .catch(() => {
                return false
            })
    }

    getAccessToken(raw = false) {
        this.validateAccessData()
        const token = this.localStorage.accessToken.getAccessToken()
        if(raw) {
            return token
        }
        return 'Bearer ' + token
    }

    logout() {
        this.localStorage.clearAccessData()
    }

    getFirebaseApp(): FirebaseApp {
        return this.firebaseApp
    }

}
