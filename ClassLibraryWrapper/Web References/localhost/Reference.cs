﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

// 
// This source code was auto-generated by Microsoft.VSDesigner, Version 4.0.30319.42000.
// 
#pragma warning disable 1591

namespace ClassLibraryWrapper.localhost {
    using System;
    using System.Web.Services;
    using System.Diagnostics;
    using System.Web.Services.Protocols;
    using System.Xml.Serialization;
    using System.ComponentModel;
    
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Web.Services.WebServiceBindingAttribute(Name="DSWSSoap", Namespace="http://tempuri.org/")]
    public partial class DSWS : System.Web.Services.Protocols.SoapHttpClientProtocol {
        
        private System.Threading.SendOrPostCallback GetUserCertificateOperationCompleted;
        
        private System.Threading.SendOrPostCallback SignDataOperationCompleted;
        
        private System.Threading.SendOrPostCallback getSignaturelLenOperationCompleted;
        
        private bool useDefaultCredentialsSetExplicitly;
        
        /// <remarks/>
        public DSWS() {
            this.Url = global::ClassLibraryWrapper.Properties.Settings.Default.ClassLibraryWrapper_localhost_DSWS;
            if ((this.IsLocalFileSystemWebService(this.Url) == true)) {
                this.UseDefaultCredentials = true;
                this.useDefaultCredentialsSetExplicitly = false;
            }
            else {
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        public new string Url {
            get {
                return base.Url;
            }
            set {
                if ((((this.IsLocalFileSystemWebService(base.Url) == true) 
                            && (this.useDefaultCredentialsSetExplicitly == false)) 
                            && (this.IsLocalFileSystemWebService(value) == false))) {
                    base.UseDefaultCredentials = false;
                }
                base.Url = value;
            }
        }
        
        public new bool UseDefaultCredentials {
            get {
                return base.UseDefaultCredentials;
            }
            set {
                base.UseDefaultCredentials = value;
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        /// <remarks/>
        public event GetUserCertificateCompletedEventHandler GetUserCertificateCompleted;
        
        /// <remarks/>
        public event SignDataCompletedEventHandler SignDataCompleted;
        
        /// <remarks/>
        public event getSignaturelLenCompletedEventHandler getSignaturelLenCompleted;
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://tempuri.org/GetUserCertificate", RequestNamespace="http://tempuri.org/", ResponseNamespace="http://tempuri.org/", Use=System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle=System.Web.Services.Protocols.SoapParameterStyle.Wrapped)]
        [return: System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] GetUserCertificate(string username) {
            object[] results = this.Invoke("GetUserCertificate", new object[] {
                        username});
            return ((byte[])(results[0]));
        }
        
        /// <remarks/>
        public void GetUserCertificateAsync(string username) {
            this.GetUserCertificateAsync(username, null);
        }
        
        /// <remarks/>
        public void GetUserCertificateAsync(string username, object userState) {
            if ((this.GetUserCertificateOperationCompleted == null)) {
                this.GetUserCertificateOperationCompleted = new System.Threading.SendOrPostCallback(this.OnGetUserCertificateOperationCompleted);
            }
            this.InvokeAsync("GetUserCertificate", new object[] {
                        username}, this.GetUserCertificateOperationCompleted, userState);
        }
        
        private void OnGetUserCertificateOperationCompleted(object arg) {
            if ((this.GetUserCertificateCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.GetUserCertificateCompleted(this, new GetUserCertificateCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://tempuri.org/SignData", RequestNamespace="http://tempuri.org/", ResponseNamespace="http://tempuri.org/", Use=System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle=System.Web.Services.Protocols.SoapParameterStyle.Wrapped)]
        [return: System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] SignData(string username, string password, [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")] byte[] data) {
            object[] results = this.Invoke("SignData", new object[] {
                        username,
                        password,
                        data});
            return ((byte[])(results[0]));
        }
        
        /// <remarks/>
        public void SignDataAsync(string username, string password, byte[] data) {
            this.SignDataAsync(username, password, data, null);
        }
        
        /// <remarks/>
        public void SignDataAsync(string username, string password, byte[] data, object userState) {
            if ((this.SignDataOperationCompleted == null)) {
                this.SignDataOperationCompleted = new System.Threading.SendOrPostCallback(this.OnSignDataOperationCompleted);
            }
            this.InvokeAsync("SignData", new object[] {
                        username,
                        password,
                        data}, this.SignDataOperationCompleted, userState);
        }
        
        private void OnSignDataOperationCompleted(object arg) {
            if ((this.SignDataCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.SignDataCompleted(this, new SignDataCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://tempuri.org/getSignaturelLen", RequestNamespace="http://tempuri.org/", ResponseNamespace="http://tempuri.org/", Use=System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle=System.Web.Services.Protocols.SoapParameterStyle.Wrapped)]
        public int getSignaturelLen(string username, string password, [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")] byte[] data) {
            object[] results = this.Invoke("getSignaturelLen", new object[] {
                        username,
                        password,
                        data});
            return ((int)(results[0]));
        }
        
        /// <remarks/>
        public void getSignaturelLenAsync(string username, string password, byte[] data) {
            this.getSignaturelLenAsync(username, password, data, null);
        }
        
        /// <remarks/>
        public void getSignaturelLenAsync(string username, string password, byte[] data, object userState) {
            if ((this.getSignaturelLenOperationCompleted == null)) {
                this.getSignaturelLenOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetSignaturelLenOperationCompleted);
            }
            this.InvokeAsync("getSignaturelLen", new object[] {
                        username,
                        password,
                        data}, this.getSignaturelLenOperationCompleted, userState);
        }
        
        private void OngetSignaturelLenOperationCompleted(object arg) {
            if ((this.getSignaturelLenCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getSignaturelLenCompleted(this, new getSignaturelLenCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        public new void CancelAsync(object userState) {
            base.CancelAsync(userState);
        }
        
        private bool IsLocalFileSystemWebService(string url) {
            if (((url == null) 
                        || (url == string.Empty))) {
                return false;
            }
            System.Uri wsUri = new System.Uri(url);
            if (((wsUri.Port >= 1024) 
                        && (string.Compare(wsUri.Host, "localHost", System.StringComparison.OrdinalIgnoreCase) == 0))) {
                return true;
            }
            return false;
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    public delegate void GetUserCertificateCompletedEventHandler(object sender, GetUserCertificateCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class GetUserCertificateCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal GetUserCertificateCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public byte[] Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((byte[])(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    public delegate void SignDataCompletedEventHandler(object sender, SignDataCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class SignDataCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal SignDataCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public byte[] Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((byte[])(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    public delegate void getSignaturelLenCompletedEventHandler(object sender, getSignaturelLenCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.6.1586.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getSignaturelLenCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getSignaturelLenCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public int Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((int)(this.results[0]));
            }
        }
    }
}

#pragma warning restore 1591