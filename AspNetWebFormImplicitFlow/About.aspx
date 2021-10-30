<%@ Page Title="About" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="About.aspx.cs" Inherits="AspNetWebFormImplicitFlow.About" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <h1>Login as: <%= User.Identity.Name %></h1>


<div class="card">
  <div class="card-header">
    <h3>Id Token</h3>
  </div>
  <div class="card-body">
    <p class="card-text">
    <asp:Label ID="lblIdToken" runat="server" Text=""></asp:Label>
    </p>
  </div>
</div>


<div class="card">
  <div class="card-header">
    <h3>Access Token</h3>
  </div>
  <div class="card-body">
    <p class="card-text">
        <asp:Label ID="lblAccessToken" runat="server" Text=""></asp:Label>
    </p>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <h3>All Claims</h3>
  </div>
  <div class="card-body">
    <p class="card-text">
    <div class="table-responsive">
        <asp:GridView ID="grdClaims" runat="server" CssClass="table table-striped table-bordered table-hover">
        </asp:GridView>
    </div>
    </p>
  </div>
</div>
    



</asp:Content>
